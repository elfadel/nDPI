/* Includes and License */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_STREAMS_PER_THREAD 			2048
#define MAX_IDLE_STREAMS_PER_THREAD 		64
#define TICK_RESOLUTION 			1000
#define MAX_CAPTURE_THREADS 			2
#define IDLE_SCAN_PERIOD 			10000 // msec
#define MAX_IDLE_TIME 				300000 // msec
#define INITIAL_THREAD_HASH 			0x03dd018b 
#define MAX_HANDLED_TCP_STREAMS 		0x10000 /* Arbitrary, 65536 */

#ifndef ETH_P_IP
#define ETH_P_IP 				0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 				0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  				0x0806
#endif

enum tcp_stream_profil {
	LATENCY_SENSITIVE,
	LATENCY_LOSS_SENSITIVE,
	LOSS_SENSITIVE,
	INSENSITIVE,
	UNKNOWN_STREAM_PROFIL,
};

enum vtl_ndpi_l3_type {
	L3_IP4,
	L3_IP6, 				/* Not yet supported */
};

struct vtl_tcp_stream_info { // Unique stream
	uint8_t gid; 			/* Graft id associated to the stream */
	uint32_t profil;
	uint32_t stream_id;
	unsigned long long int packets_processed;
	uint64_t first_seen;
	uint64_t last_seen;
	uint64_t hash_val;

	enum vtl_ndpi_l3_type l3_type;

	union {
		struct {
			uint32_t src;
			uint32_t dst;
		} v4;
		struct {
			uint64_t src[2];
			uint64_t dst[2];
		} v6;
	} ip_tuple;

	unsigned long long int total_tcp_data_len;
	uint16_t src_port;
	uint16_t dst_port;

	uint8_t is_mid_stream:1;
	uint8_t stream_fin_ack_seen:1;
	uint8_t stream_ack_seen:1;
	uint8_t detection_completed:1;
	uint8_t tls_client_hello_seen:1; 
	uint8_t tls_server_hello_seen:1;
	uint8_t reserved_00:2;
	/* This field is put to fix ndpi_detection_get_l4() invokation. 
	 * We already knew that we are processing TCP stream
	*/
	uint8_t l4_proto;

	struct ndpi_proto detected_l7_proto;
	struct ndpi_proto guessed_proto;

	struct ndpi_flow_struct *ndpi_flow;
	struct ndpi_id_struct *ndpi_src;
	struct ndpi_id_struct *ndpi_dst;
};

struct vtl_tcp_streams_tab { // All Streams capture by one thread
	pcap_t *pcap_handle; // TODO: Try equivalent with XDP fd or MAP fd

	uint8_t error_or_eof:1;
	uint8_t reserved_00:7;
	uint8_t reserved_01[3];

	unsigned long long int packets_captured;
	unsigned long long int packets_processed;
	unsigned long long int total_tcp_data_len;
	unsigned long long int detected_stream_l7_protos;

	uint64_t last_idle_scan_time;
	uint64_t last_time;

	void **ndpi_streams_active;
	unsigned long long int max_active_streams;
	unsigned long long int cur_active_streams;
	unsigned long long int total_active_streams;

	void **ndpi_streams_idle;
	unsigned long long int max_idle_streams;
	unsigned long long int cur_idle_streams;
	unsigned long long int total_idle_streams;

	struct ndpi_detection_module_struct *ndpi_struct;
};

struct vtl_capture_thread {
	struct vtl_tcp_streams_tab *streams_tab;
	pthread_t thread_id;
	int array_index;
};

static struct vtl_capture_thread capture_threads[MAX_CAPTURE_THREADS] = {};
static int capture_thread_count = MAX_CAPTURE_THREADS;
static int main_thread_shutdown = 0;
static uint32_t stream_id = 0;

static void destroy_streams_tab(struct vtl_tcp_streams_tab ** const streams_tab);

static struct vtl_tcp_streams_tab* init_streams_tab(char const * const file_or_device) {
	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
	struct vtl_tcp_streams_tab *streams_tab = (struct vtl_tcp_streams_tab *)ndpi_calloc(1, sizeof(*streams_tab));

	if(streams_tab == NULL) {
		// TODO: Log message if ndpi_calloc() doesn't provide anyone.
		return streams_tab;
	}

	if(access(file_or_device, R_OK) != 0 && errno == ENOENT) {
		streams_tab->pcap_handle = 
		pcap_open_live(file_or_device, 65535, 1, 250, pcap_error_buffer);
	}
	else {
		streams_tab->pcap_handle = 
		pcap_open_offline_with_tstamp_precision(
		file_or_device, PCAP_TSTAMP_PRECISION_MICRO, pcap_error_buffer);
	}

	if(streams_tab->pcap_handle == NULL) {
		fprintf(stderr, "pcap_open_live / pcap_open_offline_with_tstamp_precision: %s\n", pcap_error_buffer);
		destroy_streams_tab(&streams_tab);
		return NULL;
	}

	ndpi_init_prefs init_prefs = ndpi_no_prefs;
	streams_tab->ndpi_struct = ndpi_init_detection_module(init_prefs);
	if(streams_tab->ndpi_struct == NULL) {
		// TODO: Log message if ndpi_init_detection_module() doesn't provide anyone.
		destroy_streams_tab(&streams_tab);
		return NULL;
	}

	streams_tab->total_active_streams = 0;
	streams_tab->max_active_streams = MAX_STREAMS_PER_THREAD;
	streams_tab->ndpi_streams_active = (void **)ndpi_calloc(streams_tab->max_active_streams, sizeof(void *));
	if(streams_tab->ndpi_streams_active == NULL) {
		// TODO: Log message if ndpi_calloc() doesn't provide anyone.
		destroy_streams_tab(&streams_tab);
		return NULL;
	}

	streams_tab->total_idle_streams = 0;
	streams_tab->max_idle_streams = MAX_IDLE_STREAMS_PER_THREAD;
	streams_tab->ndpi_streams_idle = (void **)ndpi_calloc(streams_tab->max_idle_streams, sizeof(void *));
	if(streams_tab->ndpi_streams_idle == NULL) {
		// TODO: Log message if ndpi_calloc() doesn't provide anyone.
		destroy_streams_tab(&streams_tab);
		return NULL;
	}

	NDPI_PROTOCOL_BITMASK protos;
	NDPI_BITMASK_SET_ALL(protos);
	ndpi_set_protocol_detection_bitmask2(streams_tab->ndpi_struct, &protos);
	ndpi_finalize_initalization(streams_tab->ndpi_struct);

	return streams_tab;
}

static void vtl_destroy_tcp_stream_info(void *const node) {
	struct vtl_tcp_stream_info *const stream = (struct vtl_tcp_stream_info *)node;

	ndpi_free(stream->ndpi_dst);
	ndpi_free(stream->ndpi_src);
	ndpi_flow_free(stream->ndpi_flow);
	ndpi_free(stream);
}

static void destroy_streams_tab(struct vtl_tcp_streams_tab **const streams_tab) {
	struct vtl_tcp_streams_tab *const tab = *streams_tab;

	if(tab == NULL)
		return;

	if(tab->pcap_handle != NULL) {
		pcap_close(tab->pcap_handle);
		tab->pcap_handle = NULL;
	}

	if(tab->ndpi_struct != NULL) {
		ndpi_exit_detection_module(tab->ndpi_struct);
	}
	for(size_t i = 0; i < tab->max_active_streams; i++){
		ndpi_tdestroy(tab->ndpi_streams_active[i], vtl_destroy_tcp_stream_info);
	}
	ndpi_free(tab->ndpi_streams_active);
	ndpi_free(tab->ndpi_streams_idle);
	ndpi_free(tab);

	*streams_tab = NULL;
}

static int setup_capture_threads(char const * const file_or_device) {
	char const *file_or_default_device;
	char pcap_error_buffer[PCAP_ERRBUF_SIZE];

	if(capture_thread_count > MAX_CAPTURE_THREADS) {
		return 1;
	}

	if(file_or_device == NULL) { // Try to assign default device to capture
		file_or_default_device = pcap_lookupdev(pcap_error_buffer);
		if(file_or_default_device == NULL) {
			fprintf(stderr, "pcap_lookupdev: %s\n", pcap_error_buffer);
			return 1;
		}
	}
	else { // User specifies interface to capture or provides file to read
		file_or_default_device = file_or_device;
	}

	for(int i = 0; i < capture_thread_count; ++i) {
		capture_threads[i].streams_tab = init_streams_tab(file_or_default_device);
		if(capture_threads[i].streams_tab == NULL) {
			// Log message handled in init_streams_tab()
			return 1;
		}
	}

	return 0;
}

static int ip_tuple_to_string(struct vtl_tcp_stream_info const * const stream, 
			      char * const src_addr_str, size_t src_addr_len,
			      char * const dst_addr_str, size_t dst_addr_len) 
{
	switch(stream->l3_type) {
		case L3_IP4:
			return inet_ntop(AF_INET, (struct sockaddr_in *)&stream->ip_tuple.v4.src, 
					 src_addr_str, src_addr_len) != NULL && inet_ntop(AF_INET, 
					 (struct sockaddr_in *)&stream->ip_tuple.v4.dst, dst_addr_str, 
					 dst_addr_len) != NULL;
		case L3_IP6: // Not Yet Handle
		default:
			return 0;
	}

	return 0; // Compiler fancy :-)
}

#ifdef VERBOSE
static void print_packet_info(struct vtl_capture_thread const * const capture_thread, 
			      struct pcap_pkthdr const * const header, uint32_t tcp_data_len, 
			      struct vtl_tcp_stream_info const * const stream) 
{ // TODO: The place to classify and save info in BPF MAPS ???
	struct vtl_tcp_streams_tab const * const streams_tab = capture_thread->streams_tab;
	char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
	char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};
	char buf[256];
	int used = 0, ret;

	ret = snprintf(buf, sizeof(buf), "[%8llu, %d, %4u] %4u bytes: ", 
		       streams_tab->packets_captured, capture_thread->array_index,
		       stream->stream_id, header->caplen);
	if(ret > 0)
		used += ret;

	if(ip_tuple_to_string(stream, src_addr_str, sizeof(src_addr_str), 
			      dst_addr_str, sizeof(dst_addr_str)) != 0)
		ret = snprintf(buf+used, sizeof(buf) - used, "IP[%s -> %s]", 
			       src_addr_str, dst_addr_str);
	else
		ret = snprintf(buf+used, sizeof(buf) - used, "IP[ERROR]");

	if(ret > 0)
		used += ret;

	ret = snprintf(buf+used, sizeof(buf) - used, "-> TCP[%u -> %u, %u bytes]", 
		       stream->src_port, stream->dst_port, tcp_data_len);

	if(ret > 0)
		used += ret;

	printf("%.*s\n", used, buf);
}
#endif

static int ip_tuples_equal(struct vtl_tcp_stream_info const * const A, 
			   struct vtl_tcp_stream_info const * const B)
{
	if(A->l3_type == L3_IP4 && B->l3_type == L3_IP4) { // TODO: Align with ndpi code's in case of bugs
		return (A->ip_tuple.v4.src == B->ip_tuple.v4.src) && 
		       (A->ip_tuple.v4.dst == B->ip_tuple.v4.dst);
	}
	else //IPv6 not yet handled
		return 0;

	return 0; // Prevent compiler fancy :-)
}

static int ip_tuples_compare(struct vtl_tcp_stream_info const * const A,
			     struct vtl_tcp_stream_info const * const B) 
{
	if(A->l3_type == L3_IP4 && B->l3_type == L3_IP4) {
		if(A->ip_tuple.v4.src < B->ip_tuple.v4.src || 
		   A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
			return -1;
		if(A->ip_tuple.v4.src > B->ip_tuple.v4.src || 
		   A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
			return 1;
	}
	else if(A->l3_type == L3_IP6 && B->l3_type == L3_IP6) // IPv6
		return 0;

	if(A->src_port < B->src_port || 
	   A->dst_port < B->dst_port)
		return -1;
	else if(A->src_port > B->src_port || 
		A->dst_port > B->dst_port)
		return 1;

	return 0;
}

static void vtl_idle_scan_walker(void const * const A, ndpi_VISIT which, 
				 int depth, void * const user_data) 
{

	struct vtl_tcp_streams_tab *const streams_tab = (struct vtl_tcp_streams_tab *)
							user_data;
	struct vtl_tcp_stream_info *const stream = *(struct vtl_tcp_stream_info **)A;

	(void)depth;

	if(streams_tab == NULL || stream == NULL)
		return;

	if(streams_tab->cur_idle_streams == MAX_IDLE_STREAMS_PER_THREAD) 
		return;

	if(which == ndpi_preorder || which == ndpi_leaf) {

		if((stream->stream_fin_ack_seen == 1 && stream->stream_ack_seen == 1) ||
			stream->last_seen + MAX_IDLE_TIME < streams_tab->last_time) {

			char src_addr_str[INET6_ADDRSTRLEN+1];
			char dst_addr_str[INET6_ADDRSTRLEN+1];
			ip_tuple_to_string(stream, src_addr_str, sizeof(src_addr_str), 
					   dst_addr_str, sizeof(dst_addr_str));
			streams_tab->ndpi_streams_idle[streams_tab->cur_idle_streams++] = stream;
			streams_tab->total_idle_streams++;
		}
	}
}

static int vtl_streams_tab_node_compare(void const * const A, void const * const B) {

	struct vtl_tcp_stream_info const * const stream_info_a = (struct vtl_tcp_stream_info *)A;
	struct vtl_tcp_stream_info const * const stream_info_b = (struct vtl_tcp_stream_info *)B;

	if(stream_info_a->hash_val < stream_info_b->hash_val)
		return -1;
	else if(stream_info_a->hash_val > stream_info_b->hash_val)
		return 1;

	// Strams have the same hash value
	if(ip_tuples_equal(stream_info_a, stream_info_b) != 0 &&
		stream_info_a->src_port == stream_info_b->src_port &&
		stream_info_a->dst_port == stream_info_b->dst_port)
		return 0;

	return ip_tuples_compare(stream_info_a, stream_info_b);
}

static void check_4_idle_streams(struct vtl_tcp_streams_tab * const streams_tab) {

	if(streams_tab->last_idle_scan_time + IDLE_SCAN_PERIOD < streams_tab->last_time) {

		for(size_t idle_scan_index = 0; idle_scan_index < streams_tab->max_active_streams; 
		    ++idle_scan_index) {

			ndpi_twalk(streams_tab->ndpi_streams_active[idle_scan_index], 
				   vtl_idle_scan_walker, streams_tab);

			while(streams_tab->cur_idle_streams > 0) {
				struct vtl_tcp_stream_info * const strm = 
				(struct vtl_tcp_stream_info *)streams_tab->ndpi_streams_idle[--streams_tab->cur_idle_streams];

				if(strm->stream_fin_ack_seen == 1)
					printf("Free fin stream with id %u\n", strm->stream_id);
				else
					printf("Free idle stream with id %u\n", strm->stream_id);

				ndpi_tdelete(strm, &streams_tab->ndpi_streams_active[idle_scan_index], 
					     vtl_streams_tab_node_compare);
				vtl_destroy_tcp_stream_info(strm);
				streams_tab->cur_active_streams--;
			}
		}
		streams_tab->last_idle_scan_time = streams_tab->last_time;
	}
}

static void cbr_process_and_classify_packet(uint8_t * const args, struct pcap_pkthdr const * const header, 
					    uint8_t const * const packet) 
{
	struct vtl_capture_thread * const capture_thread = (struct vtl_capture_thread *)args;
	struct vtl_tcp_streams_tab *streams_tab;
	struct vtl_tcp_stream_info stream = {};

	size_t hashed_index;
	void * tree_result;
	struct vtl_tcp_stream_info *stream_to_process_and_class;

	int direction_changed = 0;
	struct ndpi_id_struct * ndpi_src;
	struct ndpi_id_struct * ndpi_dst;

	const struct ndpi_ethhdr *eth;
	const struct ndpi_iphdr *ip;

	uint64_t time_ms;
	const uint16_t eth_offset = 0;
	uint16_t ip_offset;
	uint16_t ip_size;

	const uint8_t *l4_ptr = NULL;
	uint16_t l4_len;

	uint16_t type;
	int thread_index = INITIAL_THREAD_HASH;

	if(capture_thread == NULL)
		return;

	streams_tab = capture_thread->streams_tab;
	if(streams_tab == NULL)
		return;

	streams_tab->packets_captured++;
	time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + 
		  header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
	streams_tab->last_time = time_ms;

	check_4_idle_streams(streams_tab);

	// Process L2 layer
	switch(pcap_datalink(streams_tab->pcap_handle)) {
		case DLT_NULL:
			if(ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002)
				type = ETH_P_IP;
			else
				type = ETH_P_IPV6;
			ip_offset = 4 + eth_offset;
			break;

		case DLT_EN10MB:
			if(header->len < sizeof(struct ndpi_ethhdr)) {
				fprintf(stderr, 
					"[%8llu, %d] Ethernet packet too short - skipping\n", 
					streams_tab->packets_captured, 
					capture_thread->array_index);
				return;
			}
			eth = (struct ndpi_ethhdr *) &packet[eth_offset];
			ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
			type = ntohs(eth->h_proto);
			switch(type) {
				case ETH_P_IP: // ipv4
					if(header->len < sizeof(struct ndpi_ethhdr) + 
							 sizeof(struct ndpi_iphdr)) {
						fprintf(stderr, 
							"[%8llu, %d] IP packet too short - skipping\n", 
							streams_tab->packets_captured, 
							capture_thread->array_index);
						return;
					}
					break;

				case ETH_P_IPV6:
				case ETH_P_ARP:
					return;
			}
			break;

		default:
			fprintf(stderr, 
				"[%8llu, %d] Unknown Ethernet packet with type 0x%X - skipping\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				pcap_datalink(streams_tab->pcap_handle));
			return;
	}

	if(type == ETH_P_IP)
		ip = (struct ndpi_iphdr *)&packet[ip_offset];
	else {
		fprintf(stderr, 
			"[%8llu, %d] Captured non IP packet with type 0x%X - skipping\n", 
			streams_tab->packets_captured, capture_thread->array_index, type);
		return;
	}
	ip_size = header->len - ip_offset;

	if(type == ETH_P_IP && header->len >= ip_offset) {
		if(header->caplen < header->len) {
			fprintf(stderr, 
				"[%8llu, %d] Captured packet size is smaller than packet size: %u < %u\n", 
				streams_tab->packets_captured, capture_thread->array_index, header->caplen, 
				header->len);
		}
	}

	// Process L3 layer = ip
	if(ip !=  NULL && ip->version == 4) {
		if(ip_size < sizeof(*ip)) {
			fprintf(stderr, 
				"[%8llu, %d] Packet smaller than header length: %u < %zu\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				ip_size, sizeof(*ip));
			return;
		}

		stream.l3_type = L3_IP4;
		if(ndpi_detection_get_l4((uint8_t *)ip, ip_size, &l4_ptr, &l4_len, &stream.l4_proto, 
					  NDPI_DETECTION_ONLY_IPV4) != 0) 
		{
			fprintf(stderr, 
				"[%8llu, %d] ndpi failed to detect l4 payload of ip packet, L4 len: %zu\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				ip_size - sizeof(*ip));
			return;
		}

		stream.ip_tuple.v4.src = ip->saddr;
		stream.ip_tuple.v4.dst = ip->daddr;

		uint32_t min_addr = (stream.ip_tuple.v4.src > stream.ip_tuple.v4.dst ? 
				    stream.ip_tuple.v4.dst : stream.ip_tuple.v4.src);
		thread_index = min_addr + ip->protocol;
	}
	else {
		fprintf(stderr, "[%8llu, %d] Non ip protocol detected: 0x%X\n", 
			streams_tab->packets_captured, capture_thread->array_index, type);
		return;
	}

	// Process L4 layer = TCP
	if(stream.l4_proto == IPPROTO_TCP) {

		const struct ndpi_tcphdr *tcp;

		if(header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
			fprintf(stderr, 
				"[%8llu, %d] Malformed TCP packet, packet size is smaller " 
				"than expected: %u < %zu\n", 
				streams_tab->packets_captured, capture_thread->array_index,
				header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
			return;
		}

		tcp = (struct ndpi_tcphdr *)l4_ptr;
		stream.is_mid_stream = (tcp->syn == 0 ? 1 : 0);
		stream.stream_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
		stream.stream_ack_seen = tcp->ack;
		stream.src_port = ntohs(tcp->source);
		stream.dst_port = ntohs(tcp->dest);
	}
	else { // Should never happened, but just in case
		fprintf(stderr, "Non TCP Packet captured - skipping\n");
		return;
	}

	/* Distribute streams to threads while keeping stability 
	   (same flow goes always to same thread) */
	thread_index += (stream.src_port < stream.dst_port ?
		         stream.dst_port : stream.src_port);
	thread_index %= capture_thread_count;
	if(thread_index != capture_thread->array_index)
		return;
	streams_tab->packets_processed++;
	streams_tab->total_tcp_data_len += l4_len;

 #ifdef VERBOSE
	print_packet_info(capture_thread, header, tcp_data_len, &len);
#endif

	/* Calculate stream hash for btree find, search(insert) */
	if(stream.l3_type == L3_IP4) {
		if(ndpi_flowv4_flow_hash(stream.l4_proto, stream.ip_tuple.v4.src, 
					 stream.ip_tuple.v4.dst, stream.src_port, 
					 stream.dst_port, 0, 0, (uint8_t *)&stream.hash_val, 
					 sizeof(stream.hash_val)) != 0)

			stream.hash_val = stream.ip_tuple.v4.src + stream.ip_tuple.v4.dst;
	}
	else
		return;

	stream.hash_val += stream.l4_proto + stream.src_port + stream.dst_port;

	hashed_index = stream.hash_val % streams_tab->max_active_streams;
	tree_result = ndpi_tfind(&stream, &streams_tab->ndpi_streams_active[hashed_index], 
				 vtl_streams_tab_node_compare);
	if(tree_result == NULL) {

		/* stream not found in btree. Switch src <-> dst and try to find it again. */
		uint32_t orig_src_ip = stream.ip_tuple.v4.src;
		uint32_t orig_dst_ip = stream.ip_tuple.v4.dst;
		uint16_t orig_src_port = stream.src_port;
		uint16_t orig_dst_port = stream.dst_port;

		stream.ip_tuple.v4.src = orig_dst_ip;
		stream.ip_tuple.v4.dst = orig_src_ip;
		stream.src_port = orig_dst_port;
		stream.dst_port = orig_src_port;

		tree_result = ndpi_tfind(&stream, 
					 &streams_tab->ndpi_streams_active[hashed_index], 
					 vtl_streams_tab_node_compare);
		if(tree_result != NULL)
			direction_changed = 1;

		stream.ip_tuple.v4.src = orig_src_ip;
		stream.ip_tuple.v4.dst = orig_dst_ip;
		stream.src_port = orig_src_port;
		stream.dst_port = orig_dst_port;
	}

	if(tree_result == NULL) {

		/* stream still not found, must be new */
		if(streams_tab->cur_active_streams == streams_tab->max_active_streams) {
			fprintf(stderr, 
				"[%8llu, %d] max streams to track reached: %llu, idle: %llu\n", 
				streams_tab->packets_captured, capture_thread->array_index,
				streams_tab->max_active_streams, streams_tab->cur_idle_streams);
			return;
		}

		stream_to_process_and_class = (struct vtl_tcp_stream_info *)
					      ndpi_malloc(sizeof(*stream_to_process_and_class));
		if(stream_to_process_and_class == NULL) {
			fprintf(stderr, "[%8llu, %d] Not enough memory for stream info.\n", 
				streams_tab->packets_captured, capture_thread->array_index);
			return;
		}

		streams_tab->cur_active_streams++;
		streams_tab->total_active_streams++;
		// TODO: Risk of bufferoverflow; fix.
		memcpy(stream_to_process_and_class, &stream, 
		       sizeof(*stream_to_process_and_class));
		stream_to_process_and_class->stream_id = stream_id++;

		stream_to_process_and_class->ndpi_flow = (struct ndpi_flow_struct *)
							 ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
		if(stream_to_process_and_class->ndpi_flow == NULL) {
			fprintf(stderr, 
				"[%8llu, %d, %4u] Not enough memory for ndpi flow struct member\n", 
				streams_tab->packets_captured, capture_thread->array_index,
				stream_to_process_and_class->stream_id);
			return;
		}
		memset(stream_to_process_and_class->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

		stream_to_process_and_class->ndpi_src = (struct ndpi_id_struct *)
							ndpi_calloc(1, SIZEOF_FLOW_STRUCT);
		if(stream_to_process_and_class->ndpi_src == NULL) {
			fprintf(stderr, 
				"[%8llu, %d, %4u] Not enough memory for src id struct\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				stream_to_process_and_class->stream_id);
			return;
		}

		stream_to_process_and_class->ndpi_dst = (struct ndpi_id_struct *)
							ndpi_calloc(1, SIZEOF_FLOW_STRUCT);
		if(stream_to_process_and_class->ndpi_dst == NULL) {
			fprintf(stderr, "[%8llu, %d, %4u] Not enough memory for dst id struct\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				stream_to_process_and_class->stream_id);
			return;
		}

		printf("[%8llu, %d, %4u] new %sstream\n", 
			streams_tab->packets_captured, thread_index, 
			stream_to_process_and_class->stream_id, 
			(stream_to_process_and_class->is_mid_stream != 0 ? "midstream-": ""));

		if(ndpi_tsearch(stream_to_process_and_class, 
				&streams_tab->ndpi_streams_active[hashed_index], 
				vtl_streams_tab_node_compare) == NULL) 
		{
			// Posiblle leak, but should never happen as we'd abort earlier.
			return;
		}

		ndpi_src = stream_to_process_and_class->ndpi_src;
		ndpi_dst = stream_to_process_and_class->ndpi_dst;
	}
	else { // Not a new flow
		stream_to_process_and_class = *(struct vtl_tcp_stream_info **)
						tree_result;

		if(direction_changed != 0) {
			ndpi_src = stream_to_process_and_class->ndpi_dst;
			ndpi_dst = stream_to_process_and_class->ndpi_src;
		}
		else {
			ndpi_src = stream_to_process_and_class->ndpi_src;
			ndpi_dst = stream_to_process_and_class->ndpi_dst;
		}
	}

	stream_to_process_and_class->packets_processed++;
	stream_to_process_and_class->total_tcp_data_len += l4_len;

	/* update timestamps; important for timeout handling */
	if(stream_to_process_and_class->first_seen == 0) {
		stream_to_process_and_class->first_seen = time_ms;
	}
	stream_to_process_and_class->last_seen = time_ms;
	/* packet in process is an ACK */
	stream_to_process_and_class->stream_ack_seen = stream.stream_ack_seen;

	/* TCP-FIN: indicates that at least one side wants to end the connection */
	if(stream.stream_fin_ack_seen != 0 && 
	   stream_to_process_and_class->stream_fin_ack_seen == 0) 
	{
		stream_to_process_and_class->stream_fin_ack_seen = 1;
		printf("[%8llu, %d, %4u] end of stream\n", 
			streams_tab->packets_captured, thread_index, 
			stream_to_process_and_class->stream_id);
		return;
	}

	// Try to use the max supported packets for detection
	if(stream_to_process_and_class->ndpi_flow->num_processed_pkts == 0xFF)
		return;
	else if(stream_to_process_and_class->ndpi_flow->num_processed_pkts == 0xFE) {
		// Last chance to guess something, better than nothing */
		uint8_t protocol_was_guessed = 0;
		
		stream_to_process_and_class->guessed_proto = 
		ndpi_detection_giveup(streams_tab->ndpi_struct, 
				      stream_to_process_and_class->ndpi_flow, 
				      1, &protocol_was_guessed); 
		if(protocol_was_guessed != 0) {
			printf("[%8llu, %d, %4d][GUESSED] proto: %s | app proto: %s | category: %s\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				stream_to_process_and_class->stream_id,
				ndpi_get_proto_name(streams_tab->ndpi_struct, 
						    stream_to_process_and_class->guessed_proto.master_protocol),
				ndpi_get_proto_name(streams_tab->ndpi_struct, 
						    stream_to_process_and_class->guessed_proto.app_protocol),
				ndpi_get_proto_name(streams_tab->ndpi_struct, 
						    stream_to_process_and_class->guessed_proto.category));
		}
		else {
			printf("[%8llu, %d, %4d][STREAM NOT CLASSIFIED]\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				stream_to_process_and_class->stream_id);
		}
	}

	stream_to_process_and_class->detected_l7_proto = 
	ndpi_detection_process_packet(streams_tab->ndpi_struct, stream_to_process_and_class->ndpi_flow, 
				      (uint8_t *)ip, ip_size, time_ms, ndpi_src, ndpi_dst);

	if(ndpi_is_protocol_detected(streams_tab->ndpi_struct, stream_to_process_and_class->detected_l7_proto) != 0 
	   && stream_to_process_and_class->detection_completed == 0) 
	{
		if(stream_to_process_and_class->detected_l7_proto.master_protocol != NDPI_PROTOCOL_UNKNOWN || 
		   stream_to_process_and_class->detected_l7_proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) 
		{
			stream_to_process_and_class->detection_completed = 1;
			streams_tab->detected_stream_l7_protos++;
			printf("[%8llu, %d, %4d][DETECTED] proto: %s | app proto: %s | category: %s\n", 
				streams_tab->packets_captured, capture_thread->array_index, 
				stream_to_process_and_class->stream_id,
				ndpi_get_proto_name(streams_tab->ndpi_struct, 
						    stream_to_process_and_class->detected_l7_proto.master_protocol),
				ndpi_get_proto_name(streams_tab->ndpi_struct, 
						    stream_to_process_and_class->detected_l7_proto.app_protocol),
				ndpi_get_proto_name(streams_tab->ndpi_struct, 
						    stream_to_process_and_class->detected_l7_proto.category));
		}
	}

	if(stream_to_process_and_class->ndpi_flow->num_extra_packets_checked < 
	   stream_to_process_and_class->ndpi_flow->max_extra_packets_to_check) 
	{
		/* TODO: class stream here according to VTL apps profiles and update BPF MAP ! */
		switch(stream_to_process_and_class->detected_l7_proto.category) 
		{
			case NDPI_PROTOCOL_CATEGORY_MEDIA:
			case NDPI_PROTOCOL_CATEGORY_VOIP:
			case NDPI_PROTOCOL_CATEGORY_STREAMING:
			case NDPI_PROTOCOL_CATEGORY_VIDEO:
				
				printf("[%llu, %d][VTL PROFILING]: TCP stream %d class to profil 1:"
				       " *latency* sensitive application\n", 
				       streams_tab->packets_captured, capture_thread->array_index,
				       stream_to_process_and_class->stream_id);
				
				stream_to_process_and_class->profil = LATENCY_SENSITIVE;
				break;

			case NDPI_PROTOCOL_CATEGORY_WEB:
			case NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS:
				
				printf("[%llu, %d][VTL PROFILING]: TCP stream %d class to profil 2:"
				       " *latency* and *loss* sensitive application\n", 
				       streams_tab->packets_captured, capture_thread->array_index,
				       stream_to_process_and_class->stream_id);
				
				stream_to_process_and_class->profil = LATENCY_LOSS_SENSITIVE;
				break;

			case NDPI_PROTOCOL_CATEGORY_MAIL:
			case NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT:
			case NDPI_PROTOCOL_CATEGORY_GAME:
			case NDPI_PROTOCOL_CATEGORY_CHAT:
			case NDPI_PROTOCOL_CATEGORY_FILE_SHARING:
				printf("[%llu, %d][VTL PROFILING]: TCP stream %d class to profil 3:"
				       " *loss* sensitive application\n", 
				       streams_tab->packets_captured, capture_thread->array_index,
				       stream_to_process_and_class->stream_id);
				
				stream_to_process_and_class->profil = LOSS_SENSITIVE;
				break;

			default:
				printf("[%llu, %d][VTL PROFILING]: TCP stream %d _default_ class to profil 4:"
				       " insensitive application\n", 
				       streams_tab->packets_captured, capture_thread->array_index, 
				       stream_to_process_and_class->stream_id);
				
				stream_to_process_and_class->profil = INSENSITIVE; // TODO: Fix !
				break;
		}
	}
}

static void run_pcap_loop(struct vtl_capture_thread const * const capture_thread) {

	if(capture_thread->streams_tab != NULL && 
	   capture_thread->streams_tab->pcap_handle != NULL) {

		if(pcap_loop(capture_thread->streams_tab->pcap_handle, 
			     -1, &cbr_process_and_classify_packet, 
			     (uint8_t *)capture_thread) == PCAP_ERROR) {
			fprintf(stderr, 
				"Error while reading pcap file: '%s'\n", 
				pcap_geterr(capture_thread->streams_tab->pcap_handle));
			
			capture_thread->streams_tab->error_or_eof = 1;
		}
	}
}

static void break_pcap_loop(struct vtl_capture_thread * const capture_thread) {

	if(capture_thread->streams_tab != NULL && 
	   capture_thread->streams_tab->pcap_handle != NULL)

		pcap_breakloop(capture_thread->streams_tab->pcap_handle);
}

static void* processing_thread(void *const ndpi_thread_arg) {
	struct vtl_capture_thread const * const capture_thread = (struct vtl_capture_thread *)
								 ndpi_thread_arg;

	printf("Starting ThdreadID %d\n", capture_thread->array_index);
	run_pcap_loop(capture_thread);
	capture_thread->streams_tab->error_or_eof = 1;
}

static int processing_threads_error_or_eof(void) {
	for(int i = 0; i < capture_thread_count; ++i) {
		if(capture_threads[i].streams_tab->error_or_eof == 0)
			return 0;
	}
	return 1;
}

static int start_capture_threads(void) {
	sigset_t thread_signal_set, old_signal_set;

	sigfillset(&thread_signal_set);
	sigdelset(&thread_signal_set, SIGINT);
	sigdelset(&thread_signal_set, SIGTERM);
	if(pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0) {
		fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
		return 1;
	}

	for(int i = 0; i < capture_thread_count; ++i) {
		capture_threads[i].array_index = i;

		if(capture_threads[i].streams_tab == NULL) {
			break;
		}

		if(pthread_create(&capture_threads[i].thread_id, NULL, 
				  processing_thread, &capture_threads[i]) != 0) {
			fprintf(stderr, "pthread_create: %s\n", strerror(errno));
			return 1;
		}
	}

	if(pthread_sigmask(SIG_BLOCK, &old_signal_set, NULL) != 0) {
		fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
		return 1;
	}

	return 0;
}

static int stop_capture_threads(void) {
	unsigned long long int total_packets_processed = 0;
	unsigned long long int total_tcp_data_len = 0;
	unsigned long long int total_streams_captured = 0;
	unsigned long long int total_streams_idle = 0;
	unsigned long long int total_streams_detected = 0;

	for(int i = 0; i < capture_thread_count; ++i)
		break_pcap_loop(&capture_threads[i]);

	printf("#########################################################"
	       " Stopping capture threads\n");

	for(int i = 0; i < capture_thread_count; ++i) {
		if(capture_threads[i].streams_tab == NULL)
			continue;

		total_packets_processed += 
		capture_threads[i].streams_tab->packets_processed;

		total_tcp_data_len += 
		capture_threads[i].streams_tab->total_tcp_data_len;
		
		total_streams_captured += 
		capture_threads[i].streams_tab->total_active_streams;
		
		total_streams_idle += 
		capture_threads[i].streams_tab->total_idle_streams;
		
		total_streams_detected += 
		capture_threads[i].streams_tab->detected_stream_l7_protos;

		printf("Stopping ThreadID %d, processed %10llu packets, %12llu bytes, "
		       "total streams: %8llu, idle streams: %8llu, detected streams: %8llu\n", 
		       capture_threads[i].array_index, 
		       capture_threads[i].streams_tab->packets_processed, 
		       capture_threads[i].streams_tab->total_tcp_data_len, 
		       capture_threads[i].streams_tab->total_active_streams, 
		       capture_threads[i].streams_tab->total_idle_streams, 
		       capture_threads[i].streams_tab->detected_stream_l7_protos);
	}

	/* total packets captured: same value for all threads
	   as packet2thread distribution happens later */
	printf("Total packets captured.: %llu\n",
		capture_threads[0].streams_tab->packets_captured);
	printf("Total packets processed: %llu\n", 
		total_packets_processed);
	printf("Total TCP data size.: %llu\n", 
		total_tcp_data_len);
	printf("Total streams captured...: %llu\n", total_streams_captured);
	printf("Total streams timed out..: %llu\n", total_streams_idle);
	printf("Total streams detected...: %llu\n", total_streams_detected);

	for (int i = 0; i < capture_thread_count; ++i) {
		if(capture_threads[i].streams_tab == NULL)
			continue;

		if(pthread_join(capture_threads[i].thread_id, NULL) != 0)
	    		fprintf(stderr, "pthread_join: %s\n", strerror(errno));

		destroy_streams_tab(&capture_threads[i].streams_tab);
	}

	return 0;
}

static void sighandler(int signum)
{
	fprintf(stderr, "Received SIGNAL %d\n", signum);

	if (main_thread_shutdown == 0) {
		
		main_thread_shutdown = 1;
		if (stop_capture_threads() != 0) {
	    		fprintf(stderr, "Failed to stop capture threads!\n");
	    		exit(EXIT_FAILURE);
		}
	} 
	else
		fprintf(stderr, 
			"Capture threads are already shutting down, just wait.\n");
}

int main(int argc, char ** argv)
{
	if (argc == 0)
		return 1;

	printf(
	   	"-------------------------\n  "
	   	" VTL ndpi engine start   \n  "
	   	"-------------------------\n\n"
	);

	if (setup_capture_threads((argc >= 2 ? argv[1] : NULL)) != 0) {
		fprintf(stderr, "%s: setup_capture_threads failed\n", argv[0]);
		return 1;
	}

	if (start_capture_threads() != 0) {
		fprintf(stderr, "%s: start_capture_threads\n", argv[0]);
		return 1;
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	while (main_thread_shutdown == 0 && processing_threads_error_or_eof() == 0)
		sleep(1);

	if (main_thread_shutdown == 0 && stop_capture_threads() != 0) {
		fprintf(stderr, "%s: stop_reader_threads\n", argv[0]);
		return 1;
	}

    return 0;
}