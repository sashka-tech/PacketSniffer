#include "packetHeader.h"
#include "packetDump.h"
#include "packetDecoder.h"
#include <time.h>

void capture_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[]) {
    int index, num_of_packets, num_of_device;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr cap_header;
	const u_char *packet, *pkt_data;
	pcap_t *pcap_handle;
    pcap_if_t *ift = NULL;

    for(index=0; index<argc; index++){
        printf("Command line parameter [%d] is %s\n",index,argv[index]);
    }    
    if (argc != 3){
        printf("You didn't specify the device and the number of intercepted packets.\n");
        index = 1;
        if(pcap_findalldevs(&ift, errbuf) == 0) {
        pcap_if_t *it = ift;
        device = it->name;
        printf("List of devices:\n");
        while (it) {
            printf("%d. %s - %s\n", index++, it->name, it->description);
            it = it->next;
        }
        printf("Enter number of device and number of packets: ");
        scanf("%d%d", &num_of_device, &num_of_packets);
        it = ift;
        index = 1;
         while (it) {
            if (num_of_device == index){
                device = it->name;
                printf("Selected: %d. %s - %s\n", index++, it->name, it->description);
                break;
            }
            it = it->next;
            index++;
        }
        } else {
            printf("error: %s\n", errbuf);
            exit(-1);
        }
    } else {
        device = argv[1];
        num_of_packets = atoi(argv[2]);
        printf("Device name and number of packets: %s %d\n", device, num_of_packets);
    }
    printf("=====================================================");

    time_t now;
    time(&now);
    printf("\nToday is %s", ctime(&now));	

	printf("Sniffing on device %s\n", device);
	
	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if(pcap_handle == NULL)
		pcap_fatal("pcap_open_live", errbuf);
	
	pcap_loop(pcap_handle, num_of_packets, capture_packet, NULL);
        
    /*while(true) { //permanent capture
		packet = pcap_next(pcap_handle, &header);
		printf("Got a %d byte packet\n", header.len);
		packet_dump(packet, header.len);
	}*/
    pcap_freealldevs(ift);
	pcap_close(pcap_handle);
}

void capture_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	int tcp_header_length, total_header_size, pkt_data_len;
	u_char *pkt_data;
	
	printf("\n==== Got a %d byte packet ====\n", cap_header->len);
	decode_ethernet(packet);
	decode_ip(packet+ETHER_HDR_LEN);
	tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));

	total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_length;
	pkt_data = (u_char *)packet + total_header_size;
	pkt_data_len = cap_header->len - total_header_size;
	if(pkt_data_len > 0) {
		printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
		packet_dump(pkt_data, pkt_data_len);
	} else
		printf("\t\t\tNo Packet Data\n");
}
