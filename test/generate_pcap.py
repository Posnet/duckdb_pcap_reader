#!/usr/bin/env python3
"""
PCAP file generator for testing DuckDB PCAP extension.

Supports creating PCAP files with:
- Microsecond or nanosecond precision
- Custom packet data
- Large files with random data
- Native or byte-swapped format
"""

import argparse
import struct
import time
import random
import sys
from pathlib import Path

# PCAP magic numbers
PCAP_MAGIC_MICRO = 0xa1b2c3d4  # Microsecond precision
PCAP_MAGIC_NANO = 0xa1b23c4d   # Nanosecond precision
PCAP_MAGIC_MICRO_SWAPPED = 0xd4c3b2a1  # Microsecond, byte-swapped
PCAP_MAGIC_NANO_SWAPPED = 0x4d3cb2a1   # Nanosecond, byte-swapped

def write_pcap_header(f, precision='micro', snaplen=65535, network=1, swapped=False):
    """Write PCAP global header."""
    if precision == 'nano':
        magic = PCAP_MAGIC_NANO_SWAPPED if swapped else PCAP_MAGIC_NANO
    else:
        magic = PCAP_MAGIC_MICRO_SWAPPED if swapped else PCAP_MAGIC_MICRO
    
    header = struct.pack('IHHiIII',
                        magic,         # magic number
                        2,            # version major
                        4,            # version minor
                        0,            # thiszone
                        0,            # sigfigs
                        snaplen,      # snaplen
                        network)      # network type
    f.write(header)

def write_packet(f, packet_data, ts_sec, ts_subsec, precision='micro'):
    """Write a single packet with header."""
    packet_header = struct.pack('IIII',
                              ts_sec,              # timestamp seconds
                              ts_subsec,           # timestamp microseconds/nanoseconds
                              len(packet_data),    # captured length
                              len(packet_data))    # original length
    f.write(packet_header)
    f.write(packet_data)

def generate_simple_pcap(filename, precision='micro'):
    """Generate a simple test PCAP with predefined packets."""
    packets = [
        (b"Hello, this is packet 1!", 1000000 if precision == 'micro' else 123456789),
        (b"Second packet with more data...", 2000000 if precision == 'micro' else 987654321),
        (b"Third packet", 3000000 if precision == 'micro' else 111111111),
        (b"Final packet with some binary data \x00\x01\x02\x03", 
         4000000 if precision == 'micro' else 999999999)
    ]
    
    if precision == 'nano':
        packets = [
            (b"Nanosecond packet 1", 123456789),
            (b"Nanosecond packet 2 with more data", 987654321),
            (b"Short", 111111111),
            (b"Final nanosecond packet with binary \x00\x01\x02", 999999999)
        ]
    
    with open(filename, 'wb') as f:
        write_pcap_header(f, precision=precision)
        
        base_time = int(time.time())
        for i, (data, subsec) in enumerate(packets):
            write_packet(f, data, base_time + i, subsec, precision)
    
    print(f"Created {precision}second-precision PCAP: {filename}")

def generate_large_pcap(filename, num_packets=10000, min_size=64, max_size=1500):
    """Generate a large PCAP file with random packets."""
    with open(filename, 'wb') as f:
        write_pcap_header(f, precision='micro', snaplen=max_size)
        
        base_time = int(time.time())
        
        for i in range(num_packets):
            # Generate random packet
            packet_size = random.randint(min_size, max_size)
            packet_data = bytes([random.randint(0, 255) for _ in range(packet_size)])
            
            # Timestamp: increment seconds every 1000 packets
            ts_sec = base_time + (i // 1000)
            ts_usec = (i % 1000) * 1000  # Spread microseconds
            
            write_packet(f, packet_data, ts_sec, ts_usec, precision='micro')
        
        # Calculate file size
        file_size = Path(filename).stat().st_size / (1024 * 1024)
        print(f"Created large PCAP: {filename}")
        print(f"  Packets: {num_packets:,}")
        print(f"  Size range: {min_size}-{max_size} bytes")
        print(f"  File size: {file_size:.2f} MB")

def generate_custom_pcap(filename, packets, precision='micro'):
    """Generate a PCAP with custom packet data."""
    with open(filename, 'wb') as f:
        write_pcap_header(f, precision=precision)
        
        base_time = int(time.time())
        
        for i, packet_data in enumerate(packets):
            if isinstance(packet_data, str):
                packet_data = packet_data.encode('utf-8')
            
            # Generate subsecond timestamp
            if precision == 'nano':
                ts_subsec = random.randint(0, 999999999)
            else:
                ts_subsec = random.randint(0, 999999)
            
            write_packet(f, packet_data, base_time + i, ts_subsec, precision)
    
    print(f"Created custom PCAP: {filename} with {len(packets)} packets")

def main():
    parser = argparse.ArgumentParser(description='Generate PCAP files for testing')
    parser.add_argument('output', help='Output PCAP filename')
    parser.add_argument('--type', choices=['simple', 'large', 'custom'], 
                       default='simple', help='Type of PCAP to generate')
    parser.add_argument('--precision', choices=['micro', 'nano'], 
                       default='micro', help='Timestamp precision')
    parser.add_argument('--packets', type=int, default=10000,
                       help='Number of packets (for large type)')
    parser.add_argument('--min-size', type=int, default=64,
                       help='Minimum packet size (for large type)')
    parser.add_argument('--max-size', type=int, default=1500,
                       help='Maximum packet size (for large type)')
    parser.add_argument('--data', nargs='+',
                       help='Custom packet data (for custom type)')
    parser.add_argument('--swapped', action='store_true',
                       help='Use byte-swapped (big-endian) format')
    
    args = parser.parse_args()
    
    # Create output directory if needed
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if args.type == 'simple':
        generate_simple_pcap(args.output, precision=args.precision)
    elif args.type == 'large':
        generate_large_pcap(args.output, 
                          num_packets=args.packets,
                          min_size=args.min_size,
                          max_size=args.max_size)
    elif args.type == 'custom':
        if not args.data:
            print("Error: --data required for custom type", file=sys.stderr)
            sys.exit(1)
        generate_custom_pcap(args.output, args.data, precision=args.precision)

if __name__ == '__main__':
    main()