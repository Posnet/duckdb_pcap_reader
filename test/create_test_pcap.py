#!/usr/bin/env python3
import struct
import time

def create_test_pcap(filename):
    with open(filename, 'wb') as f:
        # Write PCAP global header
        # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
        global_header = struct.pack('IHHiIII', 
                                   0xa1b2c3d4,  # magic number
                                   2,           # version major
                                   4,           # version minor
                                   0,           # thiszone
                                   0,           # sigfigs
                                   65535,       # snaplen
                                   1)           # network (Ethernet)
        f.write(global_header)
        
        # Write a few test packets
        test_packets = [
            b"Hello, this is packet 1!",
            b"Second packet with more data...",
            b"Third packet",
            b"Final packet with some binary data \x00\x01\x02\x03"
        ]
        
        base_time = int(time.time())
        
        for i, packet_data in enumerate(test_packets):
            # Packet header: ts_sec, ts_usec, caplen, len
            packet_header = struct.pack('IIII',
                                      base_time + i,      # ts_sec
                                      (i + 1) * 1000,     # ts_usec (microseconds)
                                      len(packet_data),   # caplen
                                      len(packet_data))   # len
            f.write(packet_header)
            f.write(packet_data)
    
    print(f"Created test pcap file: {filename}")

if __name__ == "__main__":
    create_test_pcap("data/test.pcap")