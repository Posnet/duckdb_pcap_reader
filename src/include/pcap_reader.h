#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "duckdb_extension.h"
#include <stdint.h>

// PCAP file magic numbers (microsecond precision)
#define PCAP_MAGIC_NATIVE 0xa1b2c3d4
#define PCAP_MAGIC_SWAPPED 0xd4c3b2a1

// PCAP file magic numbers (nanosecond precision)
#define PCAP_MAGIC_NANO_NATIVE 0xa1b23c4d
#define PCAP_MAGIC_NANO_SWAPPED 0x4d3cb2a1

// PCAP file header (24 bytes)
typedef struct {
    uint32_t magic_number;   // magic number
    uint16_t version_major;  // major version number
    uint16_t version_minor;  // minor version number
    int32_t  thiszone;       // GMT to local correction
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // data link type
} pcap_file_header_t;

// PCAP packet header (16 bytes)
typedef struct {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t caplen;         // number of octets of packet saved
    uint32_t len;            // actual length of packet
} pcap_packet_header_t;

// Function to register the pcap reader table function
void RegisterPcapReaderFunction(duckdb_connection connection);

#endif // PCAP_READER_H
