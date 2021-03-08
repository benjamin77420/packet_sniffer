#include "packet_sniffer.h"

FILE *logfile;

int main(){
    int sadrr_size, data_size;
    
    struct sockaddr  sadrr;
    
    unsigned char *buffer = (unsigned char *)malloc(MAX_PACKET_SIZE);
    
    logfile = fopen("packetLog.txt", "w");
    
    if(logfile == NULL){
        printf("Unable to find log file, please contact support.\n");
        return EXIT_FAILURE;
    }
    printf("\nstarting sniffing process now \n");
    
    int sock_raw = socket(AF_PACKET ,SOCK_RAW , htons(ETH_P_ALL));
    
    if(sock_raw < 0){
        printf("socket was nor created, please contact support.\n");
        return EXIT_FAILURE;
    }
    
    while(1){
        sadrr_size = sizeof sadrr;
        data_size = recvfrom(sock_raw, buffer, MAX_PACKET_SIZE, 0, &sadrr, (socklen_t*)&sadrr_size);
        
        if(data_size < 0){
            printf("Error in capturing packets, please contact support.\n");
            return EXIT_FAILURE;
        }
        
        packet_processor(buffer, data_size);
    }
    
    close(sock_raw);
    printf("sniffing process has ended, have a good day.\n");
    return EXIT_SUCCESS;
}



