/* wireguppy.c
 * Copyright © 2012 Thomas Schreiber
 * A simple pcap parser written for CS494 at Portland State University under
 * the instruction of professor Bart Massey. 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int RAW_MODE = 0;


int get16( void ) 
{
    int byte1 = getchar();
    int byte2 = getchar();
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
    int byte1 = getchar();
    int byte2 = getchar();
    int byte3 = getchar();
    int byte4 = getchar();
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

    printf( "%02x", getchar() );

    for ( i = 0; i < 5; i++) {
        printf( ":%02x", getchar() );
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
        fprintf( stderr, "Error: Currently only Ethernet packets \
                          are supported.\n" );
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
        getchar();

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

    printf( "%d", getchar() );

    for ( i = 0; i < 3; i++ )
        printf( ".%d", getchar() );

    return;
}


void get_raw_payload( int len )
{
    int i, j;
    int ch;
    char * human_read;

    human_read = calloc( len + 1, sizeof( char ) );

    printf( "Raw payload: \n" );

    for ( i = 1; i <= len; i++ ) {
        ch = getchar();

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
    int options_len     = data_offset - 5;

    printf( "Source Port: %d\n", source_port );
    printf( "Destination Port: %d\n", dest_port );
    printf( "Sequence Number: %d\n", sequence_number );
    printf( "ACK Number: %d\n", ack_number );
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

    for ( i = 0; i < options_len; i++ )
        printf( "Options: %04x\n", get32() );

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


int decode_ipv6( void )
{
    int vtf = get32();
    int version = ( vtf >> 28 );
    int traffic_class = ( ( vtf >> 20 ) & 0xff );
    int flow_label = ( vtf & 0xff );
    int payload_length = get16();
    int next_header = getchar();
    int hop_limit = getchar();

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

    if ( next_header == 6 ) {
        printf( "TCP:\n" );
        decode_tcp( payload_length );
    } else if ( next_header == 17 ) {
        printf( "UDP:\n" );
        decode_udp();
    } else
        skip_bytes( payload_length );

    return payload_length + 40;
}


int decode_ipv4( void )
{
    int byte            = getchar();
    int version         = ( byte >> 4 );
    int type_of_service = getchar();
    int length          = get16();
    int ident           = get16();
    int flags           = get16();
    int ttl             = getchar();
    int protocol        = getchar();
    int checksum        = get16();

    printf( "IPv: %d\n", version );
    printf( "TOS: %d\n", type_of_service );
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

    if ( protocol == 6 ) {
        printf( "TCP:\n" );
        decode_tcp( length - 20 );
    } else if ( protocol == 17 ) {
        printf( "UDP:\n" );
        decode_udp();
    } else
        skip_bytes( length - 20 );

    return length;
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
        assert( len >= 0 );

        for ( j = 0; j < len; j++ )
            printf( "Pad: %02x\n", getchar() & 0xff );

        ch = getchar();
        if ( ch == EOF )
            break;
        (void) ungetc( ch, stdin );

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
        else if ( lt == 0x86dd )
            lt = decode_ipv6();
        else if ( lt <= 1500 )
            skip_bytes( lt );
        else {
            fprintf( stderr, "Error: Unsupported packet type.\n" );
            exit( 1 );
        }

        ch = getchar();
        if ( ch == EOF )
            break;
        (void) ungetc( ch, stdin );

        i++;
    }

    return 0;
}


int main( int argc, const char *argv[] )
{
    if ( argc > 1 ) {
        if ( argc > 2 || strcmp( argv[1], "-r" ) != 0 ) {
            fprintf( stderr, "Error: flag not supported.\n" );
            exit( 1 );
        }
        RAW_MODE = 1;
    }

    printf( "Wireguppy\n" );

    if ( !RAW_MODE )
        decode_pcap();
    else
        decode_raw();

    return 0;
}
