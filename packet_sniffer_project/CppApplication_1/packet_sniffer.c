#include "packet_sniffer.h"


int tcp=0, udp=0, other=0, total=0, i, j;
struct sockaddr_in source,dest;

void packet_processor(unsigned char* buffer, int size_of_packet){
    // getting the IP header by creating a pointer to the section that passes 
    // the ethhdr section
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    total++;
    
    // now we will check what protocol do we have stored so we will know what
    // to with what kind of packet are will have to process
    switch(iph -> protocol){
        case TCP_PROTOCOL:// in case that the protocol is 6
            tcp++;
            read_TCP_packet(buffer, size_of_packet);
            break;
        case UDP_PROTOCOL:// in case that the protocol is 17
            udp++;
            read_UDP_packet(buffer, size_of_packet);
            break;
        default:
            other++;
            break;
    }
    printf("TCP packets: %d, UDP packets: %d, other packets: %d, total packets: %d\r", tcp, udp, other, total);
}

void print_ethernet_header(unsigned char* buffer, int size_of_packet){
    // initializing a structure of ethhdr type with the values that are stored
    // in the buffer(packet that was captured)
    struct ethhdr *eth = (struct ethhdr*)buffer;
    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet header \n");
    fprintf(logfile, "Destination address : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, "Destination address : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, "Protocol : %u \n", (unsigned short)eth->h_proto);
} 

void print_IP_header(unsigned char* buffer, int size_of_packet){
    print_ethernet_header(buffer, size_of_packet);
    
    unsigned short iphdrlen;
    // iph will exclude the ethernet header part of the packet where the ethhdr
    // has ended
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    // the ihl field contains the ip header length in total bytes/4, there for we
    // will need to multi the value of the variable by 4 to get the right length
    // of bytes to skip in the buffer the avoid initializing future structures with
    // the wrong data
    iphdrlen = iph->ihl*4;
    
    // setting the values of the sockaddr_in that is assigned to host the data of the
    // sender to 0, so it will be ready to be set with the values of the socket address
    // of the new packet, this will be done on both the source and dest structures.
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph -> saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph -> daddr;
    
    fprintf(logfile, "\n");
    fprintf(logfile, "IP header");
    fprintf(logfile, "  IP version        : %d\n",(unsigned int)iph -> version);// 4 = IPV4, 6 = IPV6
    fprintf(logfile, "  IP header length  :%d DWORDS OR %d Bytes\n", (unsigned int)iph -> version, (unsigned int)iph -> version);// the headers length in DWORDS units and bytes units
    fprintf(logfile, "  Type of service : %d\n", (unsigned int)iph -> tos);// the type of the packet service to know how the datagram should be used
    fprintf(logfile, "  IP total length : %d Bytes(size of the packet)\n", (unsigned int)ntohs(iph -> tot_len));// the size of the packet
    fprintf(logfile, "  Identification  : %d\n", ntohs(iph -> id));// the uniquely assigned 16bit ID number that will be used as an Identification number
    fprintf(logfile, "  TTL      : %d\n", (unsigned int)iph -> ttl);// the packets time to live
    fprintf(logfile, "  Protocol : %d\n", (unsigned int)iph -> protocol);// getting the number that represent the protocol of the packet 
    fprintf(logfile, "  Checksum : %d\n", ntohs(iph -> check));// the numeric value of the checksum that is stored in the IPV4 header
    fprintf(logfile, "  Source IP      : %s\n", inet_ntoa(source.sin_addr));// the IP of which the packet has been sent
    fprintf(logfile, "  Destination IP : %s\n", inet_ntoa(dest.sin_addr));// the IP of the device that the packet is descent to reach
}

void read_TCP_packet(unsigned char* buffer, int size_of_packet){
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph -> ihl*4;
    
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    int headers_size = sizeof(struct ethhdr) + iphdrlen + tcph -> doff*4;
    
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
    print_IP_header(buffer, size_of_packet);// sending the packet pointer and its size to the print_IP_header function to take the store the relevant data from it
    
    fprintf(logfile, "\n");
    fprintf(logfile, "TCP header\n");
    fprintf(logfile, "  Source port      : %u\n", ntohs(tcph -> source));
    fprintf(logfile, "  Destination port : %u\n", ntohs(tcph -> dest));
    fprintf(logfile, "  Sequence number  : %u\n", ntohs(tcph -> seq));
    fprintf(logfile, "  Acknowledge number : %u\n", ntohs(tcph ->ack_seq));
    fprintf(logfile, "  Header length : %d DWORDS OR %d Bytes\n", (unsigned int)tcph -> doff, ((unsigned int)tcph -> doff)*4);
    fprintf(logfile, "  Urgent flag          : %d\n", (unsigned int)tcph -> urg);
    fprintf(logfile, "  Acknowledgement Flag : %d\n", (unsigned int)tcph -> ack);
    fprintf(logfile, "  Push flag            : %d\n", (unsigned int)tcph -> psh);
    fprintf(logfile, "  Synchronise flag     : %d\n", (unsigned int)tcph -> syn);
    fprintf(logfile, "  Finish flag          : %d\n", (unsigned int)tcph -> fin);
    fprintf(logfile, "  Window         : %d\n", ntohs(tcph -> window));
    fprintf(logfile, "  Checksum       : %d\n", ntohs(tcph -> check));
    fprintf(logfile, "  Urgent Pointer : %d\n", tcph -> urg_ptr);
    
    fprintf(logfile, "\n");
    fprintf(logfile, "                        PACKET CONTENT                        ");
    fprintf(logfile, "\n");
    
    fprintf(logfile , "IP Header\n");
    print_sections(buffer,iphdrlen);
		
    fprintf(logfile , "TCP Header\n");
    print_sections(buffer+iphdrlen,tcph->doff*4);
		
    fprintf(logfile , "Data Payload\n");	
    print_sections(buffer+headers_size , size_of_packet-headers_size );
    
    
}

void read_UDP_packet(unsigned char* buffer, int size_of_packet){
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph -> ihl*4;
    
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct udphdr));
    
    int heders_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    
    
    fprintf(logfile, "\n\n***********************UDP Packet*************************\n");
    
    print_IP_header(buffer, size_of_packet);
    
    fprintf(logfile, "  Source port      : %d\n", ntohs(udph -> source));
    fprintf(logfile, "  Destination port : %d\n", ntohs(udph -> dest)); 
    fprintf(logfile, "  UDP length       : %d\n", ntohs(udph -> len));
    fprintf(logfile, "  UDP checksum     : %d\n", ntohs(udph -> check));
    
    fprintf(logfile, "\n");
    fprintf(logfile, "IP header\n");
    print_sections(buffer, iphdrlen);
    
    fprintf(logfile, "UDP header\n");
    print_sections(buffer+iphdrlen, sizeof udph);
    
    fprintf(logfile, "                        PACKET CONTENT                        \n");
    
    print_sections(buffer+heders_size, size_of_packet-heders_size);
    
    fprintf(logfile , "\n###########################################################");
    
}

void print_sections (unsigned char* data , int Size)
{
    for(i=0 ; i < Size ; i++){
	if( i!=0 && i%16==0){   //if one line of hex printing is complete...
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++){
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
		else fprintf(logfile , "."); //otherwise print a dot
		}
			fprintf(logfile , "\n");
	} 
		
	if(i%16==0) fprintf(logfile , "   ");
	
        fprintf(logfile , " %02X",(unsigned int)data[i]);
				
	if( i==Size-1){  //print the last spaces	
            for(j=0;j<15-i%16;j++) {
                fprintf(logfile , "   "); //extra spaces
            }		
            fprintf(logfile , "         ");	
            for(j=i-i%16 ; j<=i ; j++){
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                else 
                    fprintf(logfile , ".");
            }	
            fprintf(logfile ,  "\n" );
	}
    }
}