# DuckDB PCAP Extension

A DuckDB extension for reading PCAP (packet capture) files directly in SQL queries.

## Installation

```bash
git clone --recurse-submodules https://github.com/yourusername/duckdb_pcap.git
cd duckdb_pcap
make configure
make release
```

## Usage

```sql
-- Load the extension
LOAD 'build/release/duckdb_pcap.duckdb_extension';

-- Query packets from a PCAP file
SELECT * FROM read_pcap('capture.pcap');

-- Analyze network traffic
SELECT 
    COUNT(*) as total_packets,
    MIN(timestamp_ns) / 1e9 as start_time,
    MAX(timestamp_ns) / 1e9 as end_time,
    SUM(capture_len) as total_bytes
FROM read_pcap('network.pcap');
```

## Schema

The `read_pcap()` function returns:
- `timestamp_ns` (UBIGINT): Packet timestamp in nanoseconds
- `original_len` (UINTEGER): Original packet length
- `capture_len` (UINTEGER): Captured packet length
- `data` (BLOB): Raw packet data

## Building

```bash
# Setup
make configure

# Build
make debug    # Debug build
make release  # Release build

# Clean
make clean     # Clean build artifacts
make clean_all # Clean everything
```

## Testing

```bash
make test_debug    # Test debug build
make test_release  # Test release build
```

## Requirements

- C/C++ compiler
- CMake
- Make
- Python 3 (for testing)

## PCAP Format

This extension supports the PCAP format as specified in [draft-gharris-opsawg-pcap-01](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html).