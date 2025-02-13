#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/icmp.h>
#include "layerscpp.h"


// Callback function called by pcap for each captured packet
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
   IP ip_obj(packet);
   unsigned int protocol = ip_obj.get_ip_protocol();
   if (protocol == IPPROTO_TCP) {
    	TCP tcp_obj(packet);
   
   	unsigned int src_port = tcp_obj.get_src_port();
   	unsigned int dest_port = tcp_obj.get_dest_port();
   	
   	if(src_port == 80 || dest_port == 80){
   		http http_obj(packet);
   		printf("\n");
   		http_obj.print_ip_header();
    		http_obj.print_transport_header();
    		http_obj.print_http_header(packet);
   	}
   	if(src_port == 53 || dest_port == 53){
   		TransportLayer* transport = new TCP(packet);
   		DNS dns_obj(packet, transport);
   		printf("\n");
   		dns_obj.print_ip_header();
    		transport->print_transport_header();
    		dns_obj.parse_dns_header();
    		dns_obj.parse_domain_name();
    		
    		delete transport;
   	}
   	
   	
   	
   	
    } else if (protocol == IPPROTO_UDP) {
     	UDP udp_obj(packet);
  
   	unsigned int src_port = udp_obj.get_src_port();
   	unsigned int dest_port = udp_obj.get_dest_port();
   	
   	if(src_port == 53 || dest_port == 53){
   		TransportLayer* transport = new TCP(packet);
   		DNS dns_obj(packet, transport);
   		printf("\n");
   		dns_obj.print_ip_header();
    		transport->print_transport_header();
    		dns_obj.parse_dns_header();
    		dns_obj.parse_domain_name();
    		
    		delete transport;
   	}
   	
    }
    if (protocol == IPPROTO_ICMP) {
   	ICMP icmp_obj(packet);
   	icmp_obj.print_ip_header();
    	icmp_obj.print_icmp_header();
    }
    
   
}

int main(int argc, char **argv) {
    char *dev = "wlo1"; // Change this to your network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char *filter_exp;
    bpf_u_int32 net;
    // Open the device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
      
    filter_exp = filter_type(argc, argv);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // Capture packets indefinitely
    pcap_loop(handle, 0, packet_handler, NULL);
    // Close the handle
    pcap_close(handle);
    free(filter_exp);
    
    return 0;
}
