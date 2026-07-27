"""listeners/dns.py — DNS exfiltration listener."""
from __future__ import annotations

import base64
import socket
import time
from datetime import datetime


def _log(msg: str, level: str = "info"):
    try:
        from ui.output import log
        log(msg, level)
    except Exception:
        print(f"[{level}] {msg}")


def _listen_dns(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """DNS exfiltration listener — captures DNS queries with base64-encoded subdomains."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.settimeout(1)

        start_time = time.time()
        while state["running"]:
            try:
                data, addr = srv.recvfrom(512)
                timestamp = datetime.now().isoformat()
                source = f"{addr[0]}:{addr[1]}"

                try:
                    if len(data) > 12:
                        domain_part = data[12:]
                        labels = []
                        pos = 0
                        while pos < len(domain_part):
                            length = domain_part[pos]
                            if length == 0:
                                break
                            pos += 1
                            label = domain_part[pos:pos+length].decode("utf-8", errors="replace")
                            labels.append(label)
                            pos += length

                        domain = ".".join(labels)
                        decoded_data = ""
                        for label in labels[:-2]:
                            try:
                                padded = label + "=" * (4 - len(label) % 4)
                                decoded_data += base64.b64decode(
                                    padded, altchars=b"-_"
                                ).decode("utf-8", errors="replace")
                            except Exception:
                                decoded_data += label + "."

                        pkt = {
                            "timestamp": timestamp, "type": "dns",
                            "source": source, "domain": domain,
                            "raw": domain, "decoded": decoded_data.strip(".") or domain,
                            "size": len(data),
                        }
                        with state["lock"]:
                            state["packets"].append(pkt)
                        print(f"[DNS] {timestamp[:19]} <- {source} -> {domain}")
                        if verbose and decoded_data:
                            print(f"      Decoded: {decoded_data[:200]}")
                except Exception as e:
                    _log(f"DNS parse error: {e}", "warn")

                try:
                    response = data[:2] + b"\x84\x03" + data[4:6] + b"\x00\x00\x00\x00\x00\x00"
                    srv.sendto(response, addr)
                except Exception:
                    pass

            except socket.timeout:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    break
            except Exception as e:
                if state["running"]:
                    _log(f"DNS listener error: {e}", "warn")

        srv.close()
    except Exception as e:
        _log(f"DNS listener failed: {e}", "err")
