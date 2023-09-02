#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr {
   unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
   unsigned char ether_src_addr[ETHER_ADDR_LEN];  // Source MAC address
   unsigned short ether_type; // Type of Ethernet packet
};

/* Structure for Internet Protocol (IP) headers */
struct ip_hdr {
   unsigned char ip_version_and_header_length; // version and header length combined
   unsigned char ip_tos;          // type of service
   unsigned short ip_len;         // total length
   unsigned short ip_id;          // identification number
   unsigned short ip_frag_offset; // fragment offset and flags
   unsigned char ip_ttl;          // time to live
   unsigned char ip_type;         // protocol type
   unsigned short ip_checksum;    // checksum
   unsigned int ip_src_addr;      // source IP address
   unsigned int ip_dest_addr;     // destination IP address
};

/* Structure for Transmission Control Protocol (TCP) headers */
struct tcp_hdr {
   unsigned short tcp_src_port;   // source TCP port
   unsigned short tcp_dest_port;  // destination TCP port
   unsigned int tcp_seq;          // TCP sequence number
   unsigned int tcp_ack;          // TCP acknowledgement number
   unsigned char reserved:4;      // 4-bits from the 6-bits of reserved space
   unsigned char tcp_offset:4;    // TCP data offset for little endian host
   unsigned char tcp_flags;       // TCP flags (and 2-bits from reserved space)
#define TCP_FIN   0x01
#define TCP_SYN   0x02
#define TCP_RST   0x04
#define TCP_PUSH  0x08
#define TCP_ACK   0x10
#define TCP_URG   0x20
   unsigned short tcp_window;     // TCP window size
   unsigned short tcp_checksum;   // TCP checksum
   unsigned short tcp_urgent;     // TCP urgent pointer
};
