/* wireguppy.c
 * Copyright © 2012 Thomas Schreiber
 * A simple pcap parser written for CS494 at Portland State University under
 * the instruction of professor Bart Massey. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Globals for handling cmd line options */
int RAW_MODE     = 0;  /* Raw stream or formatted in libpcap format */
int VERBOSE_MODE = 0;  /* Print application layer payload */
FILE * PCAP_FILE;      /* File pointer to stream to be parsed */

/* These functions run getc multiple times and return a larger value */
int get16( void ); 
int get32( void );

/* These change the endianess of x */
int flip16( int x );
int flip32( int x );

/* Gets and prints address */
void get_mac( void );
void get_ipv6_addr( void );
void get_ipv4_addr( void );

/* Skip and/or output len bytes */
void skip_bytes( int len );
void get_raw_payload( int len );

/* Decode various packets */
int decode_tcp( int len );
int decode_udp( void );
int decode_icmp( int len );
int decode_icmpv6( int len );
int decode_udp_lite( int len );
int decode_ipv6( void );
int decode_ipv6_ext( int plength );
int decode_ipv4( void );
int decode_arp( void );
int decode_raw( void );

/* Decode libpcap */
int decode_pcap( void );
int get_pcap_header( void );
int get_packet_header( void );

/* Get packet type or length */
int get_length_type( void );


int get16( void ) 
{
    int byte1 = getc( PCAP_FILE );
    int byte2 = getc( PCAP_FILE );
    return ( ( byte1 << 8 ) & 0xff00 )
        | ( byte2 & 0xff );
}


int flip16( int x )
{
    return ( ( x >> 8 ) & 0xff )
        | ( ( x << 8 ) & 0xff00 );
}


int get32( void )
{
    int byte1 = getc( PCAP_FILE );
    int byte2 = getc( PCAP_FILE );
    int byte3 = getc( PCAP_FILE );
    int byte4 = getc( PCAP_FILE );
    return ( ( byte1 << 24 ) & 0xff000000 )
         | ( ( byte2 << 16 ) & 0xff0000 )
         | ( ( byte3 << 8 ) & 0xff00 )
         | ( byte4 & 0xff );
}


int flip32( int x )
{
    return ( ( x >> 24 ) & 0xff )
         | ( ( x >> 8 ) & 0xff00 )
         | ( ( x << 8 ) & 0xff0000 )
         | ( ( x << 24 ) & 0xff000000 );
}


void get_mac( void )
{
    int i;

    printf( "%02x", getc( PCAP_FILE ) );

    for ( i = 0; i < 5; i++) {
        printf( ":%02x", getc( PCAP_FILE ) );
    }

    return;
}


int get_length_type( void )
{
    int lt = get16();

    if ( lt == 0x8100 ) {
        printf( "VLAN: %04x\n", get16() );
        lt = get16();
    }

    printf( "Length/EtherType: %04x\n", lt);

    return lt;
}


/* Parses the file header */
/* May be cool to match the Link layer type up with the
 * actual name of the type:
 * http://www.tcpdump.org/linktypes.html
 */
int get_pcap_header( void )
{
    int magic_number  = flip32( get32() );
    int major_version = flip16( get16() );
    int minor_version = flip16( get16() );
    int thiszone      = flip32( get32() );
    int sigfigs       = flip32( get32() );
    int snaplen       = flip32( get32() );
    int network       = flip32( get32() );

    if ( magic_number != 0xa1b2c3d4 ) {
        fprintf( stderr, "Error: Wrong file type.\n" );
        return 1;
    }

    if ( network != 1 ) {
        fprintf( stderr, 
                "Error: Currently only Ethernet packets are supported.\n" );
        return 1;
    }

    printf( "Magic Number: %08x\n", magic_number );
    printf( "Version: %d.%d\n", major_version, minor_version );
    printf( "Timezone: %d\n", thiszone );
    printf( "Significant Figures: %d\n", sigfigs );
    printf( "Snapshot Length: %d bytes\n", snaplen );
    printf( "Link Layer Header Type: %d\n", network );

    return 0;
}


int get_packet_header( void )
{
    struct tm * timestamp;
    char buffer[ 80 ];

    time_t ts_sec         = flip32( get32() );
    unsigned int ts_usec  = flip32( get32() );
    int incl_len          = flip32( get32() );
    int orig_len          = flip32( get32() );

    timestamp = localtime( &ts_sec );
    strftime( buffer, 80, "%B %d, %Y %H:%M:%S", timestamp );
    printf( "Timestamp: %s.%06d\n", buffer, ts_usec );
    printf( "Length of packet on network: %d bytes\n", orig_len );
    printf( "Length of packet actually captured: %d bytes\n", incl_len );

    return incl_len;
}


void skip_bytes( int len )
{
    int i;

    for ( i = 0; i < len; i++ )
        getc( PCAP_FILE );

    return;
}


void get_ipv6_addr( void )
{
    int i;

    printf( "%x", get16() );

    for ( i = 0; i < 7; i++ )
        printf( ":%x", get16() );
    
    return;
}


void get_ipv4_addr( void )
{
    int i;

    printf( "%d", getc( PCAP_FILE ) );

    for ( i = 0; i < 3; i++ )
        printf( ".%d", getc( PCAP_FILE ) );

    return;
}


void get_raw_payload( int len )
{
    int i, j;
    int ch;
    char * human_read;

    if ( VERBOSE_MODE ) {

        human_read = calloc( len + 1, sizeof( char ) );

        for ( i = 1; i <= len; i++ ) {
            ch = getc( PCAP_FILE );

            printf( "%02X ", ch );
            
            if ( ch > 31 && ch < 127 )
                human_read[ i - 1 ] = ch;
            else
                human_read[ i - 1 ] = '.';

            human_read[ i ] = '\0';

            if ( i % 16 == 0 && i > 1 )
                printf( "\t%s\n", human_read + ( i - 16 ) );
            if ( i == len ) {
                for ( j = 16 - ( len % 16 ); j > 0; j-- )
                    printf( "   " );
                printf( "\t%s\n", human_read + ( i - ( len % 16 ) ) );
            }

        }

        printf( "\n" );

        free( human_read );

    } else
        skip_bytes( len );

}


int decode_tcp( int len )
{
    int i;
    int source_port     = get16();
    int dest_port       = get16();
    int sequence_number = get32();
    int ack_number      = get32();
    int flags           = get16();
    int window_size     = get16();
    int checksum        = get16();
    int urgent_p        = get16();
    int data_offset     = ( flags >> 12 );
    int options_len     = ( data_offset - 5 ) * 4;

    printf( "Source Port: %d\n", source_port );
    printf( "Destination Port: %d\n", dest_port );
    printf( "Sequence Number: %u\n", sequence_number );
    printf( "ACK Number: %u\n", ack_number );
    printf( "Flags: " );
    if ( ( flags & 0x100 ) != 0 )
        printf( "\tNS\n" );
    if ( ( flags & 0x80 ) != 0 )
        printf( "\tCWR\n" );
    if ( ( flags & 0x40 ) != 0 )
        printf( "\tECE\n" );
    if ( ( flags & 0x20 ) != 0 )
        printf( "\tURG\n" );
    if ( ( flags & 0x10 ) != 0 )
        printf( "\tACK\n" );
    if ( ( flags & 0x8 ) != 0 )
        printf( "\tPSH\n" );
    if ( ( flags & 0x4 ) != 0 )
        printf( "\tRST\n" );
    if ( ( flags & 0x2 ) != 0 )
        printf( "\tSYN\n" );
    if ( ( flags & 0x1 ) != 0 )
        printf( "\tFIN\n" );
    if ( ( flags << 7 ) == 0 )
        printf( "\n" );
    printf( "Window Size: %d\n", window_size );
    printf( "Checksum: %02x\n", checksum );
    printf( "Urgent Pointer: %02x\n", urgent_p );

    if ( options_len > 0 )
        printf( "TCP Options:\n" );
    while ( options_len > 0 ) {
        int option_type     = getc( PCAP_FILE );
        int this_option_len;
        switch ( option_type ) {
        case 0:
            printf( "\tEnd of options\n" );
            break;
        case 1:
            printf( "\tNo operation\n" );
            break;
        case 2:
            printf( "\tMax segment size\n" );
            break;
        case 3:
            printf( "\tWindow Scale\n" );
            break;
        case 4:
            printf( "\tSelective Acknowledgement permitted\n" );
            break;
        case 5:
            printf( "\tSelective Acknowledgement\n" );
            break;
        case 8:
            printf( "\tTimestamp and echo of previous timestamp\n" );
            break;
        case 14:
            printf( "\tTCP Alternate Checksum Request\n" );
            break;
        case 15:
            printf( "\tTCP Alternate Checksum Data\n" );
            break;
        default:
            printf( "\tOption Code: %d\n", option_type );
        }
        if ( option_type > 1 ) {
            this_option_len = getc( PCAP_FILE );
            if ( this_option_len > 2 ) {
                printf( "\t\tOption Data: " );
                if ( option_type == 8 ) {
                    unsigned int sender_ts = get32();
                    unsigned int echo_ts = get32();
                    printf( "\n" );
                    printf( "\t\t\tSender Timestamp: %d\n", sender_ts );
                    printf( "\t\t\tEcho Timestamp: %d", echo_ts );
                } else {
                    for ( i = 0; i < this_option_len - 2; i++ ) {
                        printf( "%d", getc( PCAP_FILE ) );
                    }
                }
                printf( "\n" );
            }
        } else
            this_option_len = 1;

        options_len -= this_option_len;
    }

    get_raw_payload( len - ( data_offset * 4 ) );
    

    return 0;
}


int decode_udp( void )
{
    int source_port = get16();
    int dest_port   = get16();
    int len         = get16();
    int checksum    = get16();

    printf( "Source Port: %d\n", source_port );
    printf( "Destination Port: %d\n", dest_port );
    printf( "Length: %d bytes\n", len );
    printf( "Checksum: %02x\n", checksum );

    get_raw_payload( len - 8 );

    return 0;
}


int decode_icmp( int len )
{
    int type     = getc( PCAP_FILE );
    int code     = getc( PCAP_FILE );
    int checksum = get16();
    int header   = get32();

    printf( "Type: %d\n", type );
    printf( "Code: %d\n", code );
    printf( "Checksum: %x\n", checksum );
    printf( "Rest of Header: %X\n", header );

    get_raw_payload( len - 8 );

    return 0;
}


int decode_icmpv6( int len )
{
    int type     = getc( PCAP_FILE );
    int code     = getc( PCAP_FILE );
    int checksum = get16();

    printf( "Type: %d\n", type );
    printf( "Code: %d\n", code );
    printf( "Checksum: %x\n", checksum );

    get_raw_payload( len - 4 );

    return 0;
}


int decode_udp_lite( int len )
{
    int source   = get16();
    int dest     = get16();
    int coverage = get16();
    int checksum = get16();

    printf( "Source Port: %d\n", source );
    printf( "Destination Port: %d\n", dest );
    printf( "Coverage: %d bytes\n", coverage );
    printf( "Checksum: %x\n", checksum );

    get_raw_payload( len - 8 );

    return 0;
}

int decode_ipv6_ext( int plength )
{
    int i, payload_length;
    int next_header = getc( PCAP_FILE );
    int len         = getc( PCAP_FILE );

    get16();
    get32();

    for ( i = 0; i < len; i++ )
        skip_bytes( 4 );

    payload_length = plength - ( 8 + ( len * 4 ) );

    if ( next_header == 0 ) {
        printf( "IPv6 Hop-by-Hop Options\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 1 ) {
        printf( "ICMP:\n" );
        decode_icmp( payload_length );
    } else if( next_header == 4 ) {
        printf( "Encapsalated IPv4:\n" );
        decode_ipv4();
    } else if ( next_header == 6 ) {
        printf( "TCP:\n" );
        decode_tcp( payload_length );
    } else if ( next_header == 17 ) {
        printf( "UDP:\n" );
        decode_udp();
    } else if ( next_header == 41 ) {
        printf( "Encapsalated IPv6:\n" );
        decode_ipv6();
    } else if ( next_header == 43 ) {
        printf( "IPv6 Routing Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 44 ) {
        printf( "IPv6 Fragment Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 50 ) {
        printf( "IPv6 Encapsulated Security Payload Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 51 ) {
        printf( "IPv6 Authentication Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 60 ) {
        printf( "IPv6 Destination Options\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 58 ) {
        printf( "ICMPv6:\n" );
        decode_icmpv6( payload_length );
    } else if ( next_header == 136 ) {
        printf( "UDP-Lite:\n" );
        decode_udp_lite( payload_length );
    } else
        skip_bytes( payload_length );

    return 8 + ( len * 4 );
}


int decode_ipv6( void )
{
    int vtf = get32();
    int version = ( vtf >> 28 );
    int traffic_class = ( ( vtf >> 20 ) & 0xff );
    int flow_label = ( vtf & 0xff );
    int payload_length = get16();
    int next_header = getc( PCAP_FILE );
    int hop_limit = getc( PCAP_FILE );

    printf( "IPv: %d\n", version );
    printf( "Traffic Class: %02x\n", traffic_class );
    printf( "Flow Label: %05x\n", flow_label );
    printf( "Payload Length: %d bytes\n", payload_length );
    printf( "Next Header: %d\n", next_header );
    printf( "Hop Limit: %d\n", hop_limit );
    printf( "Source Address: " );
    get_ipv6_addr();
    printf( "\n" );
    printf( "Destination Address: " );
    get_ipv6_addr();
    printf( "\n" );

    if ( next_header == 0 ) {
        printf( "IPv6 Hop-by-Hop Options\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 1 ) {
        printf( "ICMP:\n" );
        decode_icmp( payload_length );
    } else if( next_header == 4 ) {
        printf( "Encapsalated IPv4:\n" );
        decode_ipv4();
    } else if ( next_header == 6 ) {
        printf( "TCP:\n" );
        decode_tcp( payload_length );
    } else if ( next_header == 17 ) {
        printf( "UDP:\n" );
        decode_udp();
    } else if ( next_header == 41 ) {
        printf( "Encapsalated IPv6:\n" );
        decode_ipv6();
    } else if ( next_header == 43 ) {
        printf( "IPv6 Routing Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 44 ) {
        printf( "IPv6 Fragment Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 50 ) {
        printf( "IPv6 Encapsulated Security Payload Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 51 ) {
        printf( "IPv6 Authentication Header\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 60 ) {
        printf( "IPv6 Destination Options\n" );
        decode_ipv6_ext( payload_length );
    } else if ( next_header == 58 ) {
        printf( "ICMPv6:\n" );
        decode_icmpv6( payload_length );
    } else if ( next_header == 136 ) {
        printf( "UDP-Lite:\n" );
        decode_udp_lite( payload_length );
    } else
        skip_bytes( payload_length );

    return payload_length + 40;
}


int decode_ipv4( void )
{
    int byte            = getc( PCAP_FILE );
    int version         = ( byte >> 4 );
    int header_length   = ( byte & 0xf );
    int type_of_service = getc( PCAP_FILE );
    int diff_serv_code  = ( type_of_service >> 2 );
    int ecn             = ( type_of_service & 0x3 );
    int length          = get16();
    int ident           = get16();
    int flags           = get16();
    int ttl             = getc( PCAP_FILE );
    int protocol        = getc( PCAP_FILE );
    int checksum        = get16();

    printf( "IPv: %d\n", version );
    printf( "Header Length: %d bytes\n", ( header_length * 4 ) );
    printf( "Differentiated Services Code Point: %d\n", diff_serv_code );
    printf( "Explicit Congestion Notification: %d\n", ecn );
    printf( "Total Length: %d bytes\n", length );
    printf( "Ident: %d\n", ident );
    printf( "Flags: %04x\n", flags );
    printf( "TTL: %d\n", ttl );
    printf( "Protocol: %d\n", protocol );
    printf( "Checksum: %04x\n", checksum );
    printf( "Source Address: " );
    get_ipv4_addr();
    printf( "\n" );
    printf( "Desination Address: " );
    get_ipv4_addr();
    printf( "\n" );

    if ( header_length > 5 ) {
        int options_len = ( header_length - 5 ) * 4;
        printf( "IPv4 Options:\n" );
        while ( options_len > 0 ) {
            int this_option = getc( PCAP_FILE );
            int copied      = ( this_option >> 7 );
            int class       = ( this_option & 0x60 );
            int number      = ( this_option & 0x1f );
            int this_option_len;

            if ( number > 1 )
                this_option_len = getc( PCAP_FILE ) - 2;
            else
                this_option_len = 1;

            printf( "\tCopied: %d\n", copied);
            printf( "\tClass: %d\n", class);

            switch ( this_option ) {
            case 0:
                printf( "\t\tEnd of Option list\n" );
                break;
            case 1:
                printf( "\t\tNo Operation\n" );
                break;
            case 2:
                printf( "\t\tSecurity\n" );
                break;
            case 3:
                printf( "\t\tLoose Source Routing\n" );
                break;
            case 4:
                printf( "\t\tInternet Timestamp\n" );
                break;
            case 7:
                printf( "\t\tRecord Route\n" );
                break;
            case 8:
                printf( "\t\tStream ID\n" );
                break;
            case 9:
                printf( "\t\tStrict Source Routing\n" );
                break;
            default:
                printf( "\t\tNumber: %d\n", number );
            }
            options_len -= this_option_len;    
        }

    }

    if ( protocol == 1 ) {
        printf( "ICMP:\n" );
        decode_icmp( length - 20 );
    } else if ( protocol == 4 ) {
        printf( "Encapsalated IPv4:\n" );
        decode_ipv4();
    } else if ( protocol == 6 ) {
        printf( "TCP:\n" );
        decode_tcp( length - 20 );
    } else if ( protocol == 17 ) {
        printf( "UDP:\n" );
        decode_udp();
    } else if ( protocol == 41 ) {
        printf( "Encapsalated IPv6:\n" );
        decode_ipv6();
    } else if ( protocol == 58 ) {
        printf( "ICMPv6:\n" );
        decode_icmpv6( length - 20 );
    } else if ( protocol == 136 ) {
        printf( "UDP-Lite:\n" );
        decode_udp_lite( length - 20 );
    } else
        skip_bytes( length - 20 );

    return length;
}


int decode_arp( void )
{
    int htype = get16();
    int ptype = get16();
    int hlen  = getc( PCAP_FILE );
    int plen  = getc( PCAP_FILE );
    int oper  = get16();
    int len   = 8;

    printf( "ARP: \n" );
    printf( "Hardware Type: %d\n", htype );
    printf( "Protocol Type: %04X\n", ptype );
    printf( "Hardware Length: %d\n", hlen );
    printf( "Protocol Length: %d\n", plen );
    printf( "Operation: ");
    if ( oper == 1 )
        printf( "request\n" );
    else
        printf( "response\n" );

    printf( "Sender Hardware Address: " );
    if ( htype != 1 )
        get_raw_payload( hlen );
    else
        get_mac();
    printf( "\n" );
    len += hlen;

    printf( "Sender Protocol Address: " );
    if ( ptype == 0x0800 )
        get_ipv4_addr();
    else if ( ptype == 0x86dd )
        get_ipv6_addr();
    else
        get_raw_payload( plen );
    printf( "\n" );
    len += plen;


    printf( "Target Hardware Address: " );
    if ( htype != 1 )
        get_raw_payload( hlen );
    else
        get_mac();
    printf( "\n" );
    len += hlen;

    printf( "Target Protocol Address: " );
    if ( ptype == 0x0800 )
        get_ipv4_addr();
    else if ( ptype == 0x86dd )
        get_ipv6_addr();
    else
        get_raw_payload( plen );
    printf( "\n" );
    len += plen;

    return len;
}


int decode_pcap( void )
{
    int i, j, ch, len, lt;

    if ( get_pcap_header() != 0 )
        exit( 1 );

    i = 1;
    while ( 1 ) {
        printf( "\n" );
        printf( "\n" );
        printf( "Packet: %d\n", i );
        len = get_packet_header();

        printf( "Destination: " );
        get_mac();
        printf( "\n" );

        printf( "Source: " );
        get_mac();
        printf( "\n" );

        lt = get_length_type();
        if ( lt == 0x0800 )
            lt = decode_ipv4();
        else if ( lt == 0x0806 )
            lt = decode_arp();
        else if ( lt == 0x86dd )
            lt = decode_ipv6();
        else if ( lt <= 1500 )
            skip_bytes( lt );
        else {
            fprintf( stderr, "Error: Unsupported packet type.\n" );
            exit( 1 );
        }

        len -= 14; /* 6 src + 6 des + 2 lt */
        len -= lt;
        if ( len < 0 ) {
            fprintf( stderr, "Error: length mismatch\n" );
            exit( 1 );
        }

        for ( j = 0; j < len; j++ )
            printf( "Pad: %02x\n", getc( PCAP_FILE ) & 0xff );

        ch = getc( PCAP_FILE );
        if ( ch == EOF )
            break;
        ungetc( ch, PCAP_FILE );

        i++;
    }

    return 0;
}


int decode_raw( void )
{
    int i, ch, lt;

    i = 1;
    while ( 1 ) {
        printf( "\n" );
        printf( "\n" );
        printf( "Destination: " );
        get_mac();
        printf( "\n" );

        printf( "Source: " );
        get_mac();
        printf( "\n" );

        lt = get_length_type();
        if ( lt == 0x0800 )
            lt = decode_ipv4();
        else if ( lt == 0x0806 )
            lt = decode_arp();
        else if ( lt == 0x86dd )
            lt = decode_ipv6();
        else if ( lt <= 1500 )
            skip_bytes( lt );
        else {
            fprintf( stderr, "Error: Unsupported packet type.\n" );
            exit( 1 );
        }

        ch = getc( PCAP_FILE );
        if ( ch == EOF )
            break;
        (void) ungetc( ch, PCAP_FILE );

        i++;
    }

    return 0;
}


int main( int argc, char **argv )
{
    int opt;
    char * pcap_file_name = NULL;

    while ( ( opt = getopt( argc, argv, "rv" ) ) != -1 )
        switch ( opt ) {
            case 'r':
                RAW_MODE = 1;
                break;
            case 'v':
                VERBOSE_MODE = 1;
                break;
            case '?':
                fprintf( stderr,
                         "Error: No such option: '%c'\n",
                         optopt
                       );
                exit( 1 );
        }

    if ( optind < argc - 1 ) {
        fprintf( stderr, "Error: Too many arguments\n" );
        exit( 1 );
    }

    if ( optind == argc - 1 )
        pcap_file_name = argv[optind];

    if ( pcap_file_name ) {
        if ( !( PCAP_FILE = fopen( pcap_file_name, "rb" ) ) ) {
            fprintf( stderr, "Error: Could not open file\n" );
            exit( 1 );
        }
    } else
        PCAP_FILE = stdin;

    printf( "Wireguppy\n" );

    if ( !RAW_MODE )
        decode_pcap();
    else
        decode_raw();

    if ( PCAP_FILE != stdin ) {
        if ( fclose( PCAP_FILE ) )
            exit( 1 );
    }

    return 0;
}
