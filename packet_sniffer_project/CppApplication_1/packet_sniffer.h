#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H
#include<stdlib.h>
#include<stdio.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>	
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>	
#include<netinet/if_ether.h>	
#include<net/ethernet.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

/*we will connect the numbers that represent the protocols that we are getting*/
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define MAX_PACKET_SIZE 65536
/*writing all the global variables that will be needed to track 
 the activity of the program
 */
    extern FILE *logfile;
    extern struct sockaddr_in source,dest;
    extern int tcp, udp, other, total, i, j;	


/*declaring all the function stamps that we will use in this sniffer program
 */
    void packet_processor(unsigned char* , int);
    void print_ip_header(unsigned char* , int);
    void read_TCP_packet(unsigned char * , int );
    void read_UDP_packet(unsigned char * , int );
    void print_sections(unsigned char* , int);
#endif /* PACKET_SNIFFER_H */

