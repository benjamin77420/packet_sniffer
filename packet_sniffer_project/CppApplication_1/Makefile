# *-*MakeFile*-*

all: packet_sniffer

.PHONY: all clear

packet_sniffer: main.o packet_sniffer.o
	gcc main.o packet_sniffer.o -o packet_sniffer -lpcap
	
main.o: main.c packet_sniffer.h
	gcc  main.c -c -omain.o -lpcap
	
packet_sniffer.o: packet_sniffer.c packet_sniffer.h
	gcc  packet_sniffer.c -c -o packet_sniffer.o -lpcap
	
clear:
	rm *.o packet_sniffer