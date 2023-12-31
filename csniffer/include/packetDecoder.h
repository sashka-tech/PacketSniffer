#include <pcap.h>

void pcap_fatal(const char *failed_in, const char *errbuf) {
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}

void decode_ethernet(const u_char *header_start) {
	int i;
	const struct ether_hdr *ethernet_header;

	ethernet_header = (const struct ether_hdr *)header_start;
	printf("[[  Layer 2 :: Ethernet Header  ]]\n");
	printf("[ Source: %02x", ethernet_header->ether_src_addr[0]);
	for(i=1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);

	printf("\tDest: %02x", ethernet_header->ether_dest_addr[0]);
	for(i=1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_dest_addr[i]);
	printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start) {
	const struct ip_hdr *ip_header;

	ip_header = (const struct ip_hdr *)header_start;
	printf("\t((  Layer 3 ::: IP Header  ))\n");
    struct in_addr src_addr = {ip_header->ip_src_addr};
	printf("\t( Source: %s\t", inet_ntoa(src_addr));
    struct in_addr dest_addr = {ip_header->ip_dest_addr};
	printf("Dest: %s )\n", inet_ntoa(dest_addr));
	printf("\t( Type: %u\t", (u_int) ip_header->ip_type);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

u_int decode_tcp(const u_char *header_start) {
	u_int header_size;
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *)header_start;
	header_size = 4 * tcp_header->tcp_offset;
	
	printf("\t\t{{  Layer 4 :::: TCP Header  }}\n");
	printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
	printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
	printf("\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq));
	printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
	printf("\t\t{ Header Size: %u\tFlags: ", header_size);
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG ");
	printf(" }\n");

	return header_size;
}
