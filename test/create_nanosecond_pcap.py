#!/usr/bin/env python3
import struct
import time

def create_nanosecond_pcap(filename):
    with open(filename, 'wb') as f:
        # Write PCAP global header with nanosecond magic number
        # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
        global_header = struct.pack('IHHiIII', 
                                   0xa1b23c4d,  # nanosecond magic number
                                   2,           # version major
                                   4,           # version minor
                                   0,           # thiszone
                                   0,           # sigfigs
                                   65535,       # snaplen
                                   1)           # network (Ethernet)
        f.write(global_header)
        
        # Write test packets with nanosecond precision
        test_packets = [
            (b"Nanosecond packet 1", 123456789),  # nanoseconds
            (b"Nanosecond packet 2 with more data", 987654321),
            (b"Short", 111111111),
            (b"Final nanosecond packet with binary \x00\x01\x02", 999999999)
        ]
        
        base_time = int(time.time())
        
        for i, (packet_data, nanos) in enumerate(test_packets):
            # Packet header: ts_sec, ts_nsec, caplen, len
            packet_header = struct.pack('IIII',
                                      base_time + i,      # ts_sec
                                      nanos,              # ts_nsec (nanoseconds!)
                                      len(packet_data),   # caplen
                                      len(packet_data))   # len
            f.write(packet_header)
            f.write(packet_data)
    
    print(f"Created nanosecond-precision pcap file: {filename}")

if __name__ == "__main__":
    create_nanosecond_pcap("data/test_nano.pcap")