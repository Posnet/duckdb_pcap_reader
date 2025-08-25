#!/usr/bin/env python3
"""Test stdin support for PCAP reader extension"""

import subprocess
import sys
import os

def test_stdin_support():
    """Test that the extension can read from stdin paths"""
    
    # Get paths
    test_pcap = "test/data/test.pcap"
    extension_path = "build/debug/duckdb_pcap.duckdb_extension"
    
    if not os.path.exists(test_pcap):
        print(f"ERROR: Test file {test_pcap} not found")
        return False
    
    if not os.path.exists(extension_path):
        print(f"ERROR: Extension {extension_path} not found. Run 'make debug' first.")
        return False
    
    # Test 1: Read from /dev/stdin
    print("Test 1: Reading from /dev/stdin...")
    cmd = f"""
import duckdb
conn = duckdb.connect(config={{'allow_unsigned_extensions': True}})
conn.execute("LOAD '{extension_path}'")
result = conn.execute("SELECT COUNT(*) FROM read_pcap('/dev/stdin')").fetchone()
print(f'Count: {{result[0]}}')
"""
    
    with open(test_pcap, 'rb') as f:
        pcap_data = f.read()
    
    proc = subprocess.Popen(
        [sys.executable, '-c', cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(input=pcap_data)
    
    if proc.returncode != 0:
        print(f"  FAILED: {stderr.decode()}")
        return False
    
    output = stdout.decode().strip()
    if "Count: 4" in output:
        print(f"  SUCCESS: {output}")
    else:
        print(f"  FAILED: Expected 'Count: 4', got '{output}'")
        return False
    
    # Test 2: Read from '-'
    print("Test 2: Reading from '-'...")
    cmd = cmd.replace('/dev/stdin', '-')
    
    proc = subprocess.Popen(
        [sys.executable, '-c', cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(input=pcap_data)
    
    if proc.returncode != 0:
        print(f"  FAILED: {stderr.decode()}")
        return False
    
    output = stdout.decode().strip()
    if "Count: 4" in output:
        print(f"  SUCCESS: {output}")
    else:
        print(f"  FAILED: Expected 'Count: 4', got '{output}'")
        return False
    
    # Test 3: Verify regular file still works
    print("Test 3: Reading from regular file...")
    cmd = f"""
import duckdb
conn = duckdb.connect(config={{'allow_unsigned_extensions': True}})
conn.execute("LOAD '{extension_path}'")
result = conn.execute("SELECT COUNT(*) FROM read_pcap('{test_pcap}')").fetchone()
print(f'Count: {{result[0]}}')
"""
    
    proc = subprocess.run(
        [sys.executable, '-c', cmd],
        capture_output=True,
        text=True
    )
    
    if proc.returncode != 0:
        print(f"  FAILED: {proc.stderr}")
        return False
    
    output = proc.stdout.strip()
    if "Count: 4" in output:
        print(f"  SUCCESS: {output}")
    else:
        print(f"  FAILED: Expected 'Count: 4', got '{output}'")
        return False
    
    return True

if __name__ == "__main__":
    print("Testing PCAP stdin support...")
    success = test_stdin_support()
    if success:
        print("\nAll tests passed!")
        sys.exit(0)
    else:
        print("\nTests failed!")
        sys.exit(1)