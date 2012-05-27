COMPILER = gcc
FLAGS = -g -Wall

all: wireguppy

wireguppy: wireguppy.o
	$(COMPILER) wireguppy.o -o wireguppy

wireguppy.o: wireguppy.c
	$(COMPILER) $(FLAGS) -c wireguppy.c

clean:
	rm -rf *o wireguppy

test: test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 \
	  test11 test12 test13 test14 test15

test1: wireguppy
	@ [ ./wireguppy < tests/BITTORRENT.pcap ] && echo "Test 1 Passed"

test2: wireguppy
	@ [ ./wireguppy < tests/http.cap ]  && echo "Test 2 Passed"

test3: wireguppy
	@ [ ./wireguppy < tests/NTP_sync.pcap ] && echo "Test 3 Passed"

test4: wireguppy
	@ [ ./wireguppy < tests/packets.pcap ] && echo "Test 4 Passed"

test5: wireguppy
	@ [ ./wireguppy < tests/sample-ipv6.pcap ] && echo "Test 5 Passed"

test6: wireguppy
	@ [ ./wireguppy < tests/arp-storm.pcap ] && echo "Test 6 Passed"

test7: wireguppy
	@ [ ./wireguppy < tests/SkypeIRC.cap ] && echo "Test 7 Passed"

test8: wireguppy
	@ [ ./wireguppy < tests/tcp-ecn-sample.pcap ] && echo "Test 8 Passed"

test9: wireguppy
	@ [ ./wireguppy < tests/udp_lite_normal_coverage_8-20.pcap ] \
		&& echo "Test 9 Passed"

test10: wireguppy
	@ [ ./wireguppy < tests/v6.pcap ] && echo "Test 10 Passed"

test11: wireguppy
	@ [ ./wireguppy < tests/xmas2011.pcap ] && echo "Test 11 Passed"

test12: wireguppy
	@ [ ./wireguppy < tests/IP_in_IP.cap ] && echo "Test 12 Passed"

test13: wireguppy
	@ [ ./wireguppy < tests/IPv6_in_IP.cap ] && echo "Test 13 Passed"

test14: wireguppy
	@ [ ./wireguppy < tests/ipv6_neighbor_spoofing.cap ] \
		&& echo "Test 14 Passed"

test15: wireguppy
	@ [ ./wireguppy < tests/OSPFv3_with_AH.cap ] && echo "Test 15 Passed"
