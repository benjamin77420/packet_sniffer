# *-* MakeFile *-*
all:packet_sniffer

packet_sniffer:main.o packet_sniffer.o
	gcc main.o packet_sniffer.o -o packet_sniffer
	
main.o:main.c packet_sniffer.h
	gcc main.c -c
	
packet_sniffer.o:packet_sniffer.c packet_sniffer.h
	gcc packet_sniffer.c -c 
	
clear:
	rm -f *.o
    
