# Wireguppy
Copyright © 2012 Thomas Schreiber

## Description:
A simple pcap parser written for CS494 at Portland State University under the
instruction of professor Bart Massey. Wireguppy currently parses Ethernet
packets that contain IPv4, IPv6, or ARP packets that in turn contain TCP, UDP,
UDP-Lite, ICMP, or ICMPv6 packets.

## Synopsis:
    ./wireguppy [OPTIONS] [FILE]

## Flags supported:
    r   Raw Mode
        Takes file streams of raw captured data instead of the usual libpcap
        file format.

    v   Verbose Mode
        Prints payload data in a hex editor style format.

## Installation:
    make

## Cleanup:
    make clean

## Testing:
###Run them all with:
    make test
###Alternatively, they can be run individually with:
    make test<number>

## Resources:
TCP/IP Illustrated Volume 1 Second Edition,
    Kevin R. Fall & W. Richard Stevens, Pearson Education Inc., 2012

http://wiki.wireshark.org/Development/LibpcapFileFormat

http://wiki.wireshark.org/SampleCaptures
