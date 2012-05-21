# Wireguppy
Copyright © 2012 Thomas Schreiber

## Discription:
A simple pcap parser written for CS494 at Portland State University under the
instruction of professor Bart Massey. Wireguppy currently parses Ethernet
packets that contain IPv4 or IPv6 packets that in turn contain TCP or UDP
packets.

## Synopsis:
    ./wireguppy [-r] < STREAM

## Flags supported:
    r    Raw Mode

## Installation:
    make

## Uninstallation:
    make clean

## Testing:
    make test

## Resources:
TCP/IP Illustrated Volume 1 Second Edition,
    Kevin R. Fall & W. Richard Stevens, Pearson Education Inc., 2012
http://wiki.wireshark.org/Development/LibpcapFileFormat
http://wiki.wireshark.org/SampleCaptures
