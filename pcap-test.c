#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h> // in_addr
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

//#include "libnet-headers.h"

#define SIZE_IP_HEADER 20
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
		
		
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_int16_t ether_type; /* IP? ARP? RARP? etc */
}; // 14 byte

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* don't fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int find_ethernet_type(struct sniff_ethernet* ethernet){
	if(ntohs(ethernet->ether_type) == 0x0800){
		return 1;
	}
	else return 0;
}
int find_ip_protocol(struct sniff_ip* ip){
	if(ip->ip_p == 0x06){
		return 1;
	}
	else return 0;
}

int main(int argc, char* argv[]) {

	char* dev = argv[1]; // device name

	if (!parse(&param, argc, argv))	return -1;

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
       	/*
	 * param.dev = dev
	 * pcap_t* pcap = handle
	 */

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const struct sniff_ip *ip; /* The IP header */
		const struct sniff_tcp *tcp; /* The TCP header */

		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		/* ethernet headers are always exactly 14 bytes */
		
		u_char* offset = (u_char*) packet;
		struct sniff_ethernet* ethernet = (struct sniff_ethernet*) packet; /* The ethernet header */
		struct sniff_ip* iph = (struct sniff_ip *)(packet += SIZE_ETHERNET);
		struct sniff_tcp* tcp_ = (struct sniff_tcp*)(packet += SIZE_IP_HEADER); // ip_HL * 4 = 20byte
		
		offset += (SIZE_ETHERNET + SIZE_IP_HEADER + ((((tcp_->th_offx2) & 0xf0)>>4)*4)); // Payload
		
		if(find_ethernet_type(ethernet) != 1) continue; // not ipv4
		if(find_ip_protocol(iph) != 1) continue;

		/* Ethernet Header의 src mac / dst mac */

		printf("src mac : ");
		//ether_short
		for(int i=0; i<ETHER_ADDR_LEN; ++i){
			printf("%02X ", ethernet->ether_shost[i]);
		}

		printf("-> dst mac : ");

		//ether_dhost
		for(int i=0; i<ETHER_ADDR_LEN; ++i){
			printf("%02X ", ethernet->ether_dhost[i]);
		}

		printf("\n");
		/*        -----------------       */

		/* ip header */
		// ip source	
		printf("ip_src : %s -> ", inet_ntoa(iph->ip_src));	

		// ip dst
		printf("ip_dst : %s\n", inet_ntoa(iph->ip_dst));

		/* tcp port */
		printf("src port : %d -> dst port : %d\n", ntohs(tcp_->th_sport), ntohs(tcp_->th_dport));

		/* Payload */
		/* offset = Payload data */

		printf("payload : ");
		for(int i=0; i<10; ++i){
			printf("%c", offset[i]);
		}
		printf("\n");
		printf("----------------------------------------------------\n");

	}
	return 0;
	pcap_close(pcap);
}

