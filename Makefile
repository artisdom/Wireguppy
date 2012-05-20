COMPILER = gcc
FLAGS = -g -Wall

all: wireguppy

wireguppy: wireguppy.o
	$(COMPILER) wireguppy.o -o wireguppy

wireguppy.o: wireguppy.c
	$(COMPILER) $(FLAGS) -c wireguppy.c

test: wireguppy
	./wireguppy < tests/BITTORRENT.pcap
	./wireguppy < tests/http.cap
	./wireguppy < tests/NTP_sync.pcap
	./wireguppy < tests/packets.pcap
	./wireguppy < tests/sample-ipv6.pcap

clean:
	rm -rf *o wireguppy
