#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/icmp.h>

#include "layerscpp.h"
IP::IP(const unsigned char *packet){
	this->ip = (struct iphdr*)(packet + 14); // Skip Ethernet header (14 bytes)
	}
unsigned int IP::get_ip_protocol(){
	//printf("IP constructor\n");
	return (unsigned int)this->ip->protocol;

}

// The IP header print method
void IP::print_ip_header()
{   
    printf("Packet captured:\n");
    printf("IP Header:\n");
    printf("   |-IP Version        : %d\n", (unsigned int)this->ip->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)this->ip->ihl, ((unsigned int)(this->ip->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)this->ip->tos);
    printf("   |-IP Total Length   : %d Bytes(Size of Packet)\n", ntohs(this->ip->tot_len));
    printf("   |-Identification    : %d\n", ntohs(this->ip->id));
    printf("   |-TTL      : %d\n", (unsigned int)this->ip->ttl);
    printf("   |-Protocol : %d\n", (unsigned int)this->ip->protocol);
    printf("   |-Checksum : %d\n", ntohs(this->ip->check));
    printf("   |-Source IP        : %s\n", inet_ntoa(*(struct in_addr *)&this->ip->saddr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(*(struct in_addr *)&this->ip->daddr));

}
TCP::TCP(const unsigned char *packet): IP(packet){
	//printf("TCP constructor\n");
	this->tcp = (struct tcphdr*)(packet + 14 + this->ip->ihl * 4);
	}

	
	
// The TCP header print method
void TCP::print_transport_header() 
{   
        printf("TCP Header:\n");
        printf("   |-Source Port      : %u\n", ntohs(this->tcp->source));
        printf("   |-Destination Port : %u\n", ntohs(this->tcp->dest));
        printf("   |-Sequence : %u\n", ntohs(this->tcp->seq));
        printf("   |-Ack_seq : %u\n", ntohs(this->tcp->ack_seq));

}


unsigned int TCP::get_src_port(){
	
	return (unsigned int)ntohs(this->tcp->source);

}

unsigned int TCP::get_dest_port(){
	
	return (unsigned int)ntohs(this->tcp->dest);

}
unsigned int TCP::get_hdr_len(){
	
	return (unsigned int)ntohs(this->tcp->doff);
}
// The UDP structure constructor
UDP::UDP(const unsigned char *packet):IP(packet){
	//printf("UDP constructor\n");
	this->udp = (struct udphdr*)(packet + 14 + this->ip->ihl * 4);
}

	
// The UDP header print method
void UDP::print_transport_header(){   
        printf("UDP Header:\n");
        printf("   |-Source Port      : %u\n", ntohs(this->udp->source));
        printf("   |-Destination Port : %u\n", ntohs(this->udp->dest));
        printf("   |-Length : %u\n", ntohs(this->udp->len));

}


unsigned int UDP::get_src_port(){
	
	return (unsigned int)ntohs(this->udp->source);

}

unsigned int UDP::get_dest_port(){
	
	return (unsigned int)ntohs(this->udp->dest);

}

unsigned int UDP::get_hdr_len(){ return 0;}

// The ICMP structure constructor
ICMP::ICMP(const unsigned char *packet):IP(packet){
	//printf("ICMP constructor\n");
	this->icmp = (struct icmphdr*)(packet + 14 + this->ip->ihl * 4);
}

// The UDP header print method
void ICMP::print_icmp_header()
{   
        printf("ICMP Header:\n");
        printf("   |-type      : %d\n", (unsigned int)this->icmp->type);
        printf("   |-checksum : %d\n", ntohs(this->icmp->checksum));
        printf("   |-id : %u\n", ntohs(this->icmp->un.echo.id));
        printf("   |-sequence : %u\n", ntohs(this->icmp->un.echo.sequence));

}


// APP layer protocol
http::http(const unsigned char *packet):IP(packet), TCP(packet){
		//printf("HTTP constructor\n");
}

void http::print_http_header(const unsigned char *packet)
{
	
        int tot_h_len = 14 + this->ip->ihl * 4 + this->tcp->doff * 4;
        int payload_len = this->ip->tot_len - tot_h_len;
        
	if (payload_len <= 0) {
	printf("No HTTP payload available.\n");
	return;
	}
	
	printf("HTTP Header: \n");
	char *payload = strdup((const char*)packet + tot_h_len);  // get payload 
	if (memcmp(payload, "HTTP", 4) == 0 || memcmp(payload, "GET ", 4) == 0 ||
	    memcmp(payload, "POST", 4) == 0 || memcmp(payload, "HEAD", 4) == 0) {
		char *line = strtok(payload, "\r\n");  // Get first line
   		while (line) {
       		 printf("   |-%s\n", line);
         	if (strcmp(line + strlen(line), "\r\n\r\n") == 0) {  // Stop at end of header
           	 break;
       		}
        	line = strtok(NULL, "\r\n");  // Get next line
   		}
	} else {
	    printf("No HTTP header detected.\n");
	}
	
	

    	free(payload);
        
}

DNS::DNS(const unsigned char* packet, TransportLayer* transport):IP(packet){
	//printf("DNS constructor\n");
	int tot_h_len;
	if (this->ip->protocol == IPPROTO_TCP){
		tot_h_len = 14 + this->ip->ihl * 4 + transport->get_hdr_len() * 4;
		this->dns = (struct dnshdr*) (packet + tot_h_len);
		this->payload =  packet + tot_h_len + 12;
		}
	else if(this->ip->protocol == IPPROTO_UDP){
		tot_h_len = 14 + (this->ip->ihl * 4) + 8; 
		this->dns = (struct dnshdr*) (packet + tot_h_len);
		this->payload =  packet + tot_h_len + 12;
		}
	

}

// Function to parse and print DNS header
void DNS::parse_dns_header() {

   printf("DNS Header:\n");
   printf("   |-Transaction ID	: %u\n", ntohs(this->dns->id));
   printf("   |-Flags		: 0x%04x\n", ntohs(this->dns->flags));
   printf("   |-Questions	: %d\n", ntohs(this->dns->qdcount));
   printf("   |-Answers		: %d\n", ntohs(this->dns->ancount));
   printf("   |-Authority Records : %d\n", ntohs(this->dns->nscount));
   printf("   |-Additional Records: %d\n", ntohs(this->dns->arcount));
}
void DNS::parse_domain_name() {
    printf("Domain Name: ");
    int offset = 0;
    while (payload[offset] != 0) {
        int len = payload[offset];
        for (int i = 1; i <= len; i++) {
            printf("%c", payload[offset + i]);
        }
        offset += len + 1;
        if (payload[offset] != 0)
        	printf(".");
    }
    printf("\n");
}

// filter packets
char *filter_type(int argc, char **argv)
{
	char * filter_exp;
	
	if (argc == 5) { 
        asprintf(&filter_exp, "ip host %s and port %s", argv[2], argv[4]);
    	} else if(argc == 3 && (strcmp(argv[1], "srcip") == 0) ){
    	asprintf(&filter_exp, "ip src host %s", argv[2]);
    	} else if(argc == 3 && (strcmp(argv[1], "dstip") == 0) ){
    	asprintf(&filter_exp, "ip dst host %s", argv[2]);
   	} else if(argc == 3 && (strcmp(argv[1], "srcport") == 0) ){
    	asprintf(&filter_exp, "src port %s", argv[2]);
    	} else if(argc == 3 && (strcmp(argv[1], "dstport") == 0) ){
    	asprintf(&filter_exp, "dst port %s", argv[2]);
    	} else {
    	filter_exp = strdup("");
    	}
	return filter_exp;
}


