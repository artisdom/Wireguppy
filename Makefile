COMPILER = gcc
FLAGS = -g -Wall

all: wireguppy

wireguppy: wireguppy.o
	$(COMPILER) wireguppy.o -o wireguppy

wireguppy.o: wireguppy.c
	$(COMPILER) $(FLAGS) -c wireguppy.c

test: test1 test2 test3 test4 test5

test1: wireguppy
	[ ./wireguppy < tests/BITTORRENT.pcap ] && echo "Test 1 Passed"

test2: wireguppy
	[ ./wireguppy < tests/http.cap ]  && echo "Test 2 Passed"

test3: wireguppy
	[ ./wireguppy < tests/NTP_sync.pcap ] && echo "Test 3 Passed"

test4: wireguppy
	[ ./wireguppy < tests/packets.pcap ] && echo "Test 4 Passed"

test5: wireguppy
	[ ./wireguppy < tests/sample-ipv6.pcap ] && echo "Test 5 Passed"

clean:
	rm -rf *o wireguppy
