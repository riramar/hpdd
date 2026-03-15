#!/usr/bin/env python3
"""
Header Parsing Discrepancy Detector

This script detects header parsing discrepancies across different proxies in a chain
by testing various header mutations and comparing responses.

Based on research from:
https://www.intruder.io/research/practical-http-header-smuggling
https://blackhat.com/eu-21/briefings/schedule/#practical-http-header-smuggling-sneaking-past-reverse-proxies-to-attack-aws-and-beyond-243631633367882
https://www.youtube.com/watch?v=RAtpG6OYYNM
"""

import argparse
import requests
import sys
import os
import time
import importlib.util
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import urllib3

# Version information
VERSION = "0.1"

# Default configurations
DEFAULT_TEST_CONFIGURATIONS = [
    ("POST", "Content-Length", "0", "z"),
    ("GET", "Host", "example.com", "invalid@example#com"),
    ("POST", "Transfer-Encoding", "chunked", "invalid@ value# test$"),
    ("GET", "X-Forwarded-For", "127.0.0.1", "invalid@ip#address"),
    ("GET", "X-Forwarded-Host", "example.com", "invalid@example#com"),
    ("POST", "Expect", "100-continue", "invalid@ value# test$")
]

DEFAULT_TEST_MUTATIONS = [
    ("\x20", "space"),
    ("\x5f", "underscore"),
    ("\x2d", "hyphen"),
    ("\x09", "tab"),
    ("\x2c", "comma"),
    ("\x3b", "semicolon"),
    ("\x7a", "z"),
    ("\x00", "null byte")
]

DEFAULT_TEST_TRANSFORMATIONS = [
    ("hyphen_to_underscore", "Replace hyphens with underscores (Header-Name → Header_Name)"),
    ("case_swap", "Invert case of all alphabetic characters (Header-Name → hEADER-nAME)"),
    ("unicode_mapping", "Map characters to Unicode Mathematical Monospace equivalents (Header-Name → 𝙷𝚎𝚊𝚍𝚎𝚛-𝙽𝚊𝚖𝚎)")
]

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    """Data class to store test results"""
    status_code: int
    body_length: int
    body_lines: int
    headers_length: int
    headers_lines: int
    error: Optional[str] = None


class HeaderDiscrepancyDetector:
    """Main class for detecting header parsing discrepancies"""
    
    def __init__(self, url: str, timeout: int, user_agent: str, connection_header: str, debug: bool, skip_timeout: bool):
        self.url = url
        self.timeout = timeout
        self.user_agent = user_agent
        self.connection_header = connection_header
        self.debug = debug
        self.skip_timeout = skip_timeout
    
    # Transformation hyphen_to_underscore function
    def hyphen_to_underscore(self, header: str) -> str:
        """Transform hyphens to underscores in header name"""
        return header.replace("-", "_")
    
    # Transformation case_swap function
    def case_swap(self, header: str) -> str:
        """Swap case of all alphabetic characters in header name"""
        return header.swapcase()
    
    # Transformation unicode_mapping function (Reference: https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names)
    def unicode_mapping(self, header: str) -> str:
        """Map characters to Unicode Mathematical Monospace equivalents"""
        UNICODE_MAPPING = [
            ("a", "𝚊"),
            ("b", "𝚋"),
            ("c", "𝚌"),
            ("d", "𝚍"),
            ("e", "𝚎"),
            ("f", "𝚏"),
            ("g", "𝚐"),
            ("h", "𝚑"),
            ("i", "𝚒"),
            ("j", "𝚓"),
            ("k", "𝚔"),
            ("l", "𝚕"),
            ("m", "𝚖"),
            ("n", "𝚗"),
            ("o", "𝚘"),
            ("p", "𝚙"),
            ("q", "𝚚"),
            ("r", "𝚛"),
            ("s", "𝚜"),
            ("t", "𝚝"),
            ("u", "𝚞"),
            ("v", "𝚟"),
            ("w", "𝚠"),
            ("x", "𝚡"),
            ("y", "𝚢"),
            ("z", "𝚣"),
            ("A", "𝙰"),
            ("B", "𝙱"),
            ("C", "𝙲"),
            ("D", "𝙳"),
            ("E", "𝙴"),
            ("F", "𝙵"),
            ("G", "𝙶"),
            ("H", "𝙷"),
            ("I", "𝙸"),
            ("J", "𝙹"),
            ("K", "𝙺"),
            ("L", "𝙻"),
            ("M", "𝙼"),
            ("N", "𝙽"),
            ("O", "𝙾"),
            ("P", "𝙿"),
            ("Q", "𝚀"),
            ("R", "𝚁"),
            ("S", "𝚂"),
            ("T", "𝚃"),
            ("U", "𝚄"),
            ("V", "𝚅"),
            ("W", "𝚆"),
            ("X", "𝚇"),
            ("Y", "𝚈"),
            ("Z", "𝚉"),
            ("0", "𝟶"),
            ("1", "𝟷"),
            ("2", "𝟸"),
            ("3", "𝟹"),
            ("4", "𝟺"),
            ("5", "𝟻"),
            ("6", "𝟼"),
            ("7", "𝟽"),
            ("8", "𝟾"),
            ("9", "𝟿")
        ]
        mapping_dict = {k: v for k, v in UNICODE_MAPPING}
        transformed_header = ''.join([mapping_dict.get(char, char) for char in header])
        return transformed_header
    
    # Raw HTTP request function
    def make_raw_request(self, header: str, header_line: str, method: str) -> TestResult:
        """Make raw HTTP request with manually crafted header"""
        import socket
        from urllib.parse import urlparse

        try:
            parsed_url = urlparse(self.url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            path = parsed_url.path or '/'
            if parsed_url.query:
                path += '?' + parsed_url.query
            
            # Create raw HTTP request
            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += "Pragma: no-cache\r\n"
            request += "Cache-Control: no-cache\r\n"
            request += 'Sec-Ch-Ua: "Chromium";v="139", "Not;A=Brand";v="99"\r\n'
            request += "Sec-Ch-Ua-Mobile: ?0\r\n"
            request += 'Sec-Ch-Ua-Platform: "Windows"\r\n'
            request += "Accept-Language: en-US,en;q=0.9\r\n"
            request += "Upgrade-Insecure-Requests: 1\r\n"
            request += f"User-Agent: {self.user_agent}\r\n"
            # Add Content-Type for POST or PUT
            if method.upper() in ["POST", "PUT"]:
                request += "Content-Type: application/x-www-form-urlencoded\r\n"
                # Add Content-Length for POST or PUT if not using Content-Length or Transfer-Encoding
                if not ("content-length" in header.lower() or "transfer-encoding" in header.lower()):
                    request += "Content-Length: 0\r\n"
            request += f"{header_line}\r\n"
            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
            request += "Sec-Fetch-Site: none\r\n"
            request += "Sec-Fetch-Mode: navigate\r\n"
            request += "Sec-Fetch-User: ?1\r\n"
            request += "Sec-Fetch-Dest: document\r\n"
            request += "Priority: u=0, i\r\n"
            if "connection" not in header.lower():
                request += f"Connection: {self.connection_header}\r\n"
            request += "\r\n"
            # If Transfer-Encoding header is present, add '0\r\n\r\n' as the request body
            if "transfer-encoding" in header.lower():
                request += "0\r\n\r\n"
            
            # Print raw request if debug is enabled
            if hasattr(self, 'debug') and self.debug:
                print("\n" + "\u2500" * 20 + " > RAW REQUEST > " + "\u2500" * 20)
                print(request)
                print("\u2500" * 20 + " < RAW REQUEST < " + "\u2500" * 20 + "\n")

            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if parsed_url.scheme == 'https':
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.send(request.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    return TestResult(status_code=0, body_length=-1, body_lines=-1, headers_length=-1, headers_lines=-1, error="Socket timed out while receiving data")
            
            sock.close()
            
            # Parse response
            response_str = response.decode('utf-8', errors='ignore')
            lines = response_str.split('\r\n')
            if lines:
                status_line = lines[0]
                status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else -1
                # Find headers and body
                body_start = response_str.find('\r\n\r\n')
                if body_start != -1:
                    headers_str = response_str[:body_start]
                    body = response_str[body_start + 4:]
                    body_length = len(body.encode('utf-8'))
                    body_lines = body.count('\n') + (1 if body else 0)
                    headers_length = len(headers_str.encode('utf-8'))
                    headers_lines = headers_str.count('\n') + (1 if headers_str else 0)
                else:
                    body_length = 0
                    body_lines = 0
                    headers_length = 0
                    headers_lines = 0
                return TestResult(
                    status_code=status_code,
                    body_length=body_length,
                    body_lines=body_lines,
                    headers_length=headers_length,
                    headers_lines=headers_lines
                )
            return TestResult(status_code=-1, body_length=-1, body_lines=-1, headers_length=-1, headers_lines=-1, error="Invalid response")
        except Exception as e:
            if str(e) == "timed out":
                return TestResult(status_code=0, body_length=-1, body_lines=-1, headers_length=-1, headers_lines=-1, error=str(e))
            else:
                return TestResult(status_code=-1, body_length=-1, body_lines=-1, headers_length=-1, headers_lines=-1, error=str(e))

    # Request with rate limit handling
    def make_request_with_rate_limit_handling(self, header: str, header_line: str, method: str) -> TestResult:
        """Make request with automatic handling of 429 Too Many Requests"""
        result = self.make_raw_request(header, header_line, method)
        
        # Check for 429 Too Many Requests
        if result.status_code == 429:
            print(f"  ⚠ Received 429 Too Many Requests, waiting 30 seconds before retrying...")
            time.sleep(30)
            result = self.make_raw_request(header, header_line, method)
            
            # If still 429, abort
            if result.status_code == 429:
                print(f"  ✗ Received 429 Too Many Requests again after retry. Aborting script execution.")
                sys.exit(1)
        
        return result

    def test_header_discrepancy_transformations(self, header: str, valid_value: str, invalid_value: str, function_name: str, transformation_description: str, baseline_valid: TestResult, baseline_invalid: TestResult, quit_on_first: bool, method: str, deviation: int, confirm: bool) -> List[Dict]:
        """Test header parsing discrepancies with transformation parameters"""
        findings = []
        
        print("\u2500" * 80)
        print(f"Header        : {header}")
        print(f"Transformation: {transformation_description}")
        print("\u2500" * 80)
        
        # Apply transformation using the specified function
        try:
            transformation_func = getattr(self, function_name)
            transformed_header = transformation_func(header)
        except AttributeError:
            print(f"  ✗ Transformation function '{function_name}' not found")
            print()
            return findings
        except Exception as e:
            print(f"  ✗ Error executing transformation function '{function_name}': {e}")
            print()
            return findings
        
        # Validate that transformation returned a string
        if not isinstance(transformed_header, str):
            print(f"  ✗ Transformation function '{function_name}' must return a string, got {type(transformed_header).__name__}")
            print()
            return findings
        
        # Skip if no transformation occurred
        if transformed_header == header:
            print(f"  No transformation applied - '{function_name}' did not change header '{header}'")
            print()
            return findings
        
        print(f"Case 1 - Header transformation: {header} → {transformed_header}")

        # Calculate padding for display headers to align output
        transformed_header_valid = f"{transformed_header}: {valid_value}"
        transformed_header_invalid = f"{transformed_header}: {invalid_value}"
        max_display_len = max(len(transformed_header_valid), len(transformed_header_invalid))
        
        # Make transformed valid request
        transformed_valid = self.make_request_with_rate_limit_handling(header, transformed_header_valid, method)
        if transformed_valid.status_code == -1:
            print(f"  Transformed Valid request failed ({transformed_valid.error}), retrying...")
            transformed_valid = self.make_request_with_rate_limit_handling(header, transformed_header_valid, method)
        if transformed_valid.status_code == -1:
            print(f"  Transformed Valid request failed ({transformed_valid.error}) twice, skipping this transformation.")
            print()
            return findings
        if transformed_valid.status_code == 0:
            print(f"  Transformed Valid request timed out, retrying to confirm...")
            transformed_valid = self.make_request_with_rate_limit_handling(header, transformed_header_valid, method)
        if transformed_valid.status_code == 0:
            if self.skip_timeout:
                print(f"  Transformed Valid request timed out ({transformed_valid.error}), skipping this transformation.")
                print()
                return findings
            print(f"  Transformed Valid request timed out ({transformed_valid.error}), confirmed.")
        print(f"  Transformed Valid   ({transformed_header_valid}){' ' * (max_display_len - len(transformed_header_valid))}: Status={transformed_valid.status_code:<4} | Body Lines={transformed_valid.body_lines:<4} | Body Length={transformed_valid.body_length:<6} | Headers Lines={transformed_valid.headers_lines:<3} | Headers Length={transformed_valid.headers_length:<4}")

        # Make transformed invalid request
        transformed_invalid = self.make_request_with_rate_limit_handling(header, transformed_header_invalid, method)
        if transformed_invalid.status_code == -1:
            print(f"  Transformed Invalid request failed ({transformed_invalid.error}), retrying...")
            transformed_invalid = self.make_request_with_rate_limit_handling(header, transformed_header_invalid, method)
        if transformed_invalid.status_code == -1:
            print(f"  Transformed Invalid request failed ({transformed_invalid.error}) twice, skipping this transformation.")
            print()
            return findings
        if transformed_invalid.status_code == 0:
            print(f"  Transformed Invalid request timed out ({transformed_invalid.error}), retrying to confirm...")
            transformed_invalid = self.make_request_with_rate_limit_handling(header, transformed_header_invalid, method)
        if transformed_invalid.status_code == 0:
            if self.skip_timeout:
                print(f"  Transformed Invalid request timed out ({transformed_invalid.error}), skipping this transformation.")
                print()
                return findings
            print(f"  Transformed Invalid request timed out ({transformed_invalid.error}), confirmed.")
        print(f"  Transformed Invalid ({transformed_header_invalid}){' ' * (max_display_len - len(transformed_header_invalid))}: Status={transformed_invalid.status_code:<4} | Body Lines={transformed_invalid.body_lines:<4} | Body Length={transformed_invalid.body_length:<6} | Headers Lines={transformed_invalid.headers_lines:<3} | Headers Length={transformed_invalid.headers_length:<4}")
        
        # Check for discrepancy using body and headers lines and lengths with deviation
        def within_deviation(val1, val2, dev):
            """Check if val1 and val2 are within dev% of each other based on the larger value"""
            if val1 == val2:
                return True
            max_val = max(abs(val1), abs(val2))
            if max_val == 0:
                return True
            percentage_diff = (abs(val1 - val2) / max_val) * 100
            return percentage_diff <= dev

        baseline_same_status_code = (
            baseline_valid.status_code == transformed_valid.status_code
        )

        transformed_different_status_code = (
            (baseline_invalid.status_code != transformed_invalid.status_code) and
            (baseline_valid.status_code != transformed_invalid.status_code)
        )

        baseline_same_body_lines = (
            baseline_valid.status_code == transformed_valid.status_code and
            baseline_valid.body_lines == transformed_valid.body_lines
        )

        transformed_different_body_lines = (
            (baseline_invalid.body_lines != transformed_invalid.body_lines) and
            (baseline_valid.body_lines != transformed_invalid.body_lines)
        )

        baseline_same_headers_lines = (
            baseline_valid.status_code == transformed_valid.status_code and
            baseline_valid.headers_lines == transformed_valid.headers_lines
        )

        transformed_different_headers_lines = (
            (baseline_invalid.headers_lines != transformed_invalid.headers_lines) and
            (baseline_valid.headers_lines != transformed_invalid.headers_lines)
        )

        baseline_same_body_length = (
            baseline_valid.status_code == transformed_valid.status_code and
            within_deviation(baseline_valid.body_length, transformed_valid.body_length, deviation)
        )

        transformed_different_body_length = (
            (not within_deviation(baseline_invalid.body_length, transformed_invalid.body_length, deviation)) and
            (not within_deviation(baseline_valid.body_length, transformed_invalid.body_length, deviation))
        )

        baseline_same_headers_length = (
            baseline_valid.status_code == transformed_valid.status_code and
            within_deviation(baseline_valid.headers_length, transformed_valid.headers_length, deviation)
        )

        transformed_different_headers_length = (
            (not within_deviation(baseline_invalid.headers_length, transformed_invalid.headers_length, deviation)) and
            (not within_deviation(baseline_valid.headers_length, transformed_invalid.headers_length, deviation))
        )

        # Helper function to confirm discrepancy by retesting
        def confirm_transformation_discrepancy(discrepancy_type, method):
            """Confirm discrepancy by retesting the same transformation requests"""
            print(f"  ↻ Confirming {discrepancy_type} discrepancy by retesting...")
            
            # Retest transformed valid request
            confirm_valid = self.make_request_with_rate_limit_handling(header, transformed_header_valid, method)
            if confirm_valid.status_code == -1:
                print(f"    Confirmation Valid request failed, skipping confirmation")
                return False
            
            # Retest transformed invalid request  
            confirm_invalid = self.make_request_with_rate_limit_handling(header, transformed_header_invalid, method)
            if confirm_invalid.status_code == -1:
                print(f"    Confirmation Invalid request failed, skipping confirmation")
                return False
            
            # Print confirmation results
            print(f"    Transformed Valid   ({transformed_header_valid}){' ' * (max_display_len - len(transformed_header_valid))}: Status={confirm_valid.status_code:<4} | Body Lines={confirm_valid.body_lines:<4} | Body Length={confirm_valid.body_length:<6} | Headers Lines={confirm_valid.headers_lines:<3} | Headers Length={confirm_valid.headers_length:<4}")
            print(f"    Transformed Invalid ({transformed_header_invalid}){' ' * (max_display_len - len(transformed_header_invalid))}: Status={confirm_invalid.status_code:<4} | Body Lines={confirm_invalid.body_lines:<4} | Body Length={confirm_invalid.body_length:<6} | Headers Lines={confirm_invalid.headers_lines:<3} | Headers Length={confirm_invalid.headers_length:<4}")
            
            # Check the same criteria that triggered the original discrepancy
            if discrepancy_type == 'status_code':
                baseline_same = (baseline_valid.status_code == confirm_valid.status_code)
                transformed_different = ((baseline_invalid.status_code != confirm_invalid.status_code) and
                                       (baseline_valid.status_code != confirm_invalid.status_code))
                return baseline_same and transformed_different
            
            elif discrepancy_type == 'body_lines':
                baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                               baseline_valid.body_lines == confirm_valid.body_lines)
                transformed_different = ((baseline_invalid.body_lines != confirm_invalid.body_lines) and
                                       (baseline_valid.body_lines != confirm_invalid.body_lines))
                return baseline_same and transformed_different
            
            elif discrepancy_type == 'headers_lines':
                baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                               baseline_valid.headers_lines == confirm_valid.headers_lines)
                transformed_different = ((baseline_invalid.headers_lines != confirm_invalid.headers_lines) and
                                       (baseline_valid.headers_lines != confirm_invalid.headers_lines))
                return baseline_same and transformed_different
            
            elif discrepancy_type == 'body_length':
                baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                               within_deviation(baseline_valid.body_length, confirm_valid.body_length, deviation))
                transformed_different = ((not within_deviation(baseline_invalid.body_length, confirm_invalid.body_length, deviation)) and
                                       (not within_deviation(baseline_valid.body_length, confirm_invalid.body_length, deviation)))
                return baseline_same and transformed_different
            
            elif discrepancy_type == 'headers_length':
                baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                               within_deviation(baseline_valid.headers_length, confirm_valid.headers_length, deviation))
                transformed_different = ((not within_deviation(baseline_invalid.headers_length, confirm_invalid.headers_length, deviation)) and
                                       (not within_deviation(baseline_valid.headers_length, confirm_invalid.headers_length, deviation)))
                return baseline_same and transformed_different
            
            return False

        # Check order: status_code, body_lines, headers_lines, body_length, headers_length
        if baseline_same_status_code and transformed_different_status_code:
            # Confirm discrepancy if confirmation is enabled
            confirmed = True
            if confirm:
                confirmed = confirm_transformation_discrepancy('status_code', method)
                if not confirmed:
                    print(f"  ⚠ Initial status_code discrepancy could not be confirmed, skipping")
                    print(f"  ✓ No confirmed discrepancy detected")
                    print()
                    return findings
                else:
                    print(f"  ✓ Status_code discrepancy confirmed!")
            
            if confirmed:
                finding = {
                    'case': 1,
                    'transformation': function_name,
                    'transformation_description': transformation_description,
                    'original_header': header,
                    'transformed_header': transformed_header,
                    'method': method,
                    'valid_value': valid_value,
                    'invalid_value': invalid_value,
                    'discrepancy_type': 'status_code',
                    'baseline_valid': (baseline_valid.status_code),
                    'baseline_invalid': (baseline_invalid.status_code),
                    'transformed_valid': (transformed_valid.status_code),
                    'transformed_invalid': (transformed_invalid.status_code)
                }
                findings.append(finding)
                print(f"\n☢ WARNING! {method} | {header} → {transformed_header} | V:{valid_value} | I:{invalid_value} | STATUS CODE | BV {baseline_valid.status_code} BI {baseline_invalid.status_code} | TV {transformed_valid.status_code} TI {transformed_invalid.status_code}")
                print(f"  Baseline valid ({baseline_valid.status_code}) matches transformed valid ({transformed_valid.status_code})")
                print(f"  BUT baseline invalid ({baseline_invalid.status_code}) differs from transformed invalid ({transformed_invalid.status_code})")
                print(f"  AND baseline valid ({baseline_valid.status_code}) differs from transformed invalid ({transformed_invalid.status_code})")
                print(f"  This suggests the transformation affects header parsing differently on {self.url}!")
                if quit_on_first:
                    print(f"\nExiting on first discrepancy detected.")
                    return findings
        elif baseline_same_body_lines and transformed_different_body_lines:
            # Confirm discrepancy if confirmation is enabled
            confirmed = True
            if confirm:
                confirmed = confirm_transformation_discrepancy('body_lines', method)
                if not confirmed:
                    print(f"  ⚠ Initial body_lines discrepancy could not be confirmed, skipping")
                    print(f"  ✓ No confirmed discrepancy detected")
                    print()
                    return findings
                else:
                    print(f"  ✓ Body_lines discrepancy confirmed!")
            
            if confirmed:
                finding = {
                    'case': 1,
                    'transformation': function_name,
                    'transformation_description': transformation_description,
                    'original_header': header,
                    'transformed_header': transformed_header,
                    'method': method,
                    'valid_value': valid_value,
                    'invalid_value': invalid_value,
                    'discrepancy_type': 'body_lines',
                    'baseline_valid': (baseline_valid.status_code, baseline_valid.body_lines),
                    'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.body_lines),
                    'transformed_valid': (transformed_valid.status_code, transformed_valid.body_lines),
                    'transformed_invalid': (transformed_invalid.status_code, transformed_invalid.body_lines)
                }
                findings.append(finding)
                body_lines_diff = abs(baseline_invalid.body_lines - transformed_invalid.body_lines)
                print(f"\n☢ WARNING! {method} | {header} → {transformed_header} | V:{valid_value} | I:{invalid_value} | BODY LINES ({body_lines_diff}) | BV {baseline_valid.status_code}/{baseline_valid.body_lines} BI {baseline_invalid.status_code}/{baseline_invalid.body_lines} | TV {transformed_valid.status_code}/{transformed_valid.body_lines} TI {transformed_invalid.status_code}/{transformed_invalid.body_lines}")
                print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.body_lines}) matches transformed valid ({transformed_valid.status_code}/{transformed_valid.body_lines})")
                print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.body_lines}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.body_lines})")
                print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.body_lines}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.body_lines})")
                print(f"  This suggests the transformation affects header parsing differently on {self.url}!")
                if quit_on_first:
                    print(f"\nExiting on first discrepancy detected.")
                    return findings
        elif baseline_same_headers_lines and transformed_different_headers_lines:
            # Confirm discrepancy if confirmation is enabled
            confirmed = True
            if confirm:
                confirmed = confirm_transformation_discrepancy('headers_lines', method)
                if not confirmed:
                    print(f"  ⚠ Initial headers_lines discrepancy could not be confirmed, skipping")
                    print(f"  ✓ No confirmed discrepancy detected")
                    print()
                    return findings
                else:
                    print(f"  ✓ Headers_lines discrepancy confirmed!")
            
            if confirmed:
                finding = {
                    'case': 1,
                    'transformation': function_name,
                    'transformation_description': transformation_description,
                    'original_header': header,
                    'transformed_header': transformed_header,
                    'method': method,
                    'valid_value': valid_value,
                    'invalid_value': invalid_value,
                    'discrepancy_type': 'headers_lines',
                    'baseline_valid': (baseline_valid.status_code, baseline_valid.headers_lines),
                    'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.headers_lines),
                    'transformed_valid': (transformed_valid.status_code, transformed_valid.headers_lines),
                    'transformed_invalid': (transformed_invalid.status_code, transformed_invalid.headers_lines)
                }
                findings.append(finding)
                headers_lines_diff = abs(baseline_invalid.headers_lines - transformed_invalid.headers_lines)
                print(f"\n☢ WARNING! {method} | {header} → {transformed_header} | V:{valid_value} | I:{invalid_value} | HEADERS LINES ({headers_lines_diff}) | BV {baseline_valid.status_code}/{baseline_valid.headers_lines} BI {baseline_invalid.status_code}/{baseline_invalid.headers_lines} | TV {transformed_valid.status_code}/{transformed_valid.headers_lines} TI {transformed_invalid.status_code}/{transformed_invalid.headers_lines}")
                print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_lines}) matches transformed valid ({transformed_valid.status_code}/{transformed_valid.headers_lines})")
                print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.headers_lines}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.headers_lines})")
                print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_lines}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.headers_lines})")
                print(f"  This suggests the transformation affects header parsing differently on {self.url}!")
                if quit_on_first:
                    print(f"\nExiting on first discrepancy detected.")
                    return findings
        elif baseline_same_body_length and transformed_different_body_length:
            # Confirm discrepancy if confirmation is enabled
            confirmed = True
            if confirm:
                confirmed = confirm_transformation_discrepancy('body_length', method)
                if not confirmed:
                    print(f"  ⚠ Initial body_length discrepancy could not be confirmed, skipping")
                    print(f"  ✓ No confirmed discrepancy detected")
                    print()
                    return findings
                else:
                    print(f"  ✓ Body_length discrepancy confirmed!")
            
            if confirmed:
                # Calculate percentage differences for body length
                max_val_bv_tv = max(abs(baseline_valid.body_length), abs(transformed_valid.body_length))
                diff_bv_tv = (abs(baseline_valid.body_length - transformed_valid.body_length) / max_val_bv_tv * 100) if max_val_bv_tv > 0 else 0
                
                max_val_bi_ti = max(abs(baseline_invalid.body_length), abs(transformed_invalid.body_length))
                diff_bi_ti = (abs(baseline_invalid.body_length - transformed_invalid.body_length) / max_val_bi_ti * 100) if max_val_bi_ti > 0 else 0
                
                max_val_bv_ti = max(abs(baseline_valid.body_length), abs(transformed_invalid.body_length))
                diff_bv_ti = (abs(baseline_valid.body_length - transformed_invalid.body_length) / max_val_bv_ti * 100) if max_val_bv_ti > 0 else 0
                
                finding = {
                    'case': 1,
                    'transformation': function_name,
                    'transformation_description': transformation_description,
                    'original_header': header,
                    'transformed_header': transformed_header,
                    'method': method,
                    'valid_value': valid_value,
                    'invalid_value': invalid_value,
                    'discrepancy_type': 'body_length',
                    'baseline_valid': (baseline_valid.status_code, baseline_valid.body_length),
                    'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.body_length),
                    'transformed_valid': (transformed_valid.status_code, transformed_valid.body_length),
                    'transformed_invalid': (transformed_invalid.status_code, transformed_invalid.body_length)
                }
                findings.append(finding)
                print(f"\n☢ WARNING! {method} | {header} → {transformed_header} | V:{valid_value} | I:{invalid_value} | BODY LENGTH | {deviation}% deviation | BV {baseline_valid.status_code}/{baseline_valid.body_length} BI {baseline_invalid.status_code}/{baseline_invalid.body_length} | TV {transformed_valid.status_code}/{transformed_valid.body_length} TI {transformed_invalid.status_code}/{transformed_invalid.body_length}")
                print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.body_length}) matches transformed valid ({transformed_valid.status_code}/{transformed_valid.body_length}) - Difference: {diff_bv_tv:.2f}%")
                print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.body_length}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.body_length}) - Difference: {diff_bi_ti:.2f}%")
                print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.body_length}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.body_length}) - Difference: {diff_bv_ti:.2f}%")
                print(f"  AND the deviation used during comparison of the body lengths was {deviation}%.")
                print(f"  This suggests the transformation affects header parsing differently on {self.url}!")
                if quit_on_first:
                    print(f"\nExiting on first discrepancy detected.")
                    return findings
        elif baseline_same_headers_length and transformed_different_headers_length:
            # Confirm discrepancy if confirmation is enabled
            confirmed = True
            if confirm:
                confirmed = confirm_transformation_discrepancy('headers_length', method)
                if not confirmed:
                    print(f"  ⚠ Initial headers_length discrepancy could not be confirmed, skipping")
                    print(f"  ✓ No confirmed discrepancy detected")
                    print()
                    return findings
                else:
                    print(f"  ✓ Headers_length discrepancy confirmed!")
            
            if confirmed:
                # Calculate percentage differences for headers length
                max_val_bv_tv = max(abs(baseline_valid.headers_length), abs(transformed_valid.headers_length))
                diff_bv_tv = (abs(baseline_valid.headers_length - transformed_valid.headers_length) / max_val_bv_tv * 100) if max_val_bv_tv > 0 else 0
                
                max_val_bi_ti = max(abs(baseline_invalid.headers_length), abs(transformed_invalid.headers_length))
                diff_bi_ti = (abs(baseline_invalid.headers_length - transformed_invalid.headers_length) / max_val_bi_ti * 100) if max_val_bi_ti > 0 else 0
                
                max_val_bv_ti = max(abs(baseline_valid.headers_length), abs(transformed_invalid.headers_length))
                diff_bv_ti = (abs(baseline_valid.headers_length - transformed_invalid.headers_length) / max_val_bv_ti * 100) if max_val_bv_ti > 0 else 0
                
                finding = {
                    'case': 1,
                    'transformation': function_name,
                    'transformation_description': transformation_description,
                    'original_header': header,
                    'transformed_header': transformed_header,
                    'method': method,
                    'valid_value': valid_value,
                    'invalid_value': invalid_value,
                    'discrepancy_type': 'headers_length',
                    'baseline_valid': (baseline_valid.status_code, baseline_valid.headers_length),
                    'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.headers_length),
                    'transformed_valid': (transformed_valid.status_code, transformed_valid.headers_length),
                    'transformed_invalid': (transformed_invalid.status_code, transformed_invalid.headers_length)
                }
                findings.append(finding)
                print(f"\n☢ WARNING! {method} | {header} → {transformed_header} | V:{valid_value} | I:{invalid_value} | HEADERS LENGTH | {deviation}% deviation | BV {baseline_valid.status_code}/{baseline_valid.headers_length} BI {baseline_invalid.status_code}/{baseline_invalid.headers_length} | TV {transformed_valid.status_code}/{transformed_valid.headers_length} TI {transformed_invalid.status_code}/{transformed_invalid.headers_length}")
                print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_length}) matches transformed valid ({transformed_valid.status_code}/{transformed_valid.headers_length}) - Difference: {diff_bv_tv:.2f}%")
                print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.headers_length}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.headers_length}) - Difference: {diff_bi_ti:.2f}%")
                print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_length}) differs from transformed invalid ({transformed_invalid.status_code}/{transformed_invalid.headers_length}) - Difference: {diff_bv_ti:.2f}%")
                print(f"  AND the deviation used during comparison of the headers lengths was {deviation}%.")
                print(f"  This suggests the transformation affects header parsing differently on {self.url}!")
                if quit_on_first:
                    print(f"\nExiting on first discrepancy detected.")
                    return findings
        else:
            print(f"  ✓ No discrepancy detected")

        print()
        return findings

    def test_header_discrepancy_mutations(self, header: str, valid_value: str, invalid_value: str, mutation: str, mutation_name: str, baseline_valid: TestResult, baseline_invalid: TestResult, quit_on_first: bool, method: str, deviation: int, confirm: bool) -> List[Dict]:
        """Test header parsing discrepancies with mutation parameters"""
        findings = []
        
        hex_value = '\\x' + ''.join(f'{ord(c):02x}' for c in mutation)
        name_part = mutation_name if mutation_name else ""
        print("\u2500" * 80)
        print(f"Header   : {header}")
        print(f"Mutation : {hex_value} ({name_part})")
        print("\u2500" * 80)
        
        # Each position is a distinct mutation variation, named after the comment (excluding exception notes)
        positions = [
            (0, "Mutation before header name"),
            (1, "Mutation + space before header name"),
            (2, "Mutation after header name"),
            (3, "Space + mutation after header name"),
            (4, "Mutation + space after header name"),
            (5, "Space + mutation + space after header name"),
            (6, "Mutation after colon + space"),
            (7, "Mutation + space after colon"),
            (8, "Space + mutation + space after colon"),
            (9, "Mutation after value"),
            (10, "Space + mutation after value")
        ]
        
        # Skip positions that are not valid for space mutation
        if mutation == ' ':
            skip_indices = {1, 3, 4, 5, 7, 8, 10}
            # Get the position descriptions before filtering
            skipped_positions = [(i, positions[i][1]) for i in skip_indices if i < len(positions)]
            # Filter out the positions
            positions = [p for idx, p in enumerate(positions) if idx not in skip_indices]
            print(f"Note: Skipping mutation {hex_value} ({name_part}) for positions:")
            for pos, desc in skipped_positions:
                print(f"  Position {pos} ({desc})")
            print()
        
        # Test each mutation position
        for case, (pos, pos_desc) in enumerate(positions, 1):
            print(f"Case {case} - Position {pos} ({pos_desc})")

            # Generate mutated headers and display headers based on position
            test_variations = []

            if pos == 0:  # before header name
                test_variations.append((
                    f"{mutation}{header}: {valid_value}",
                    f"{mutation}{header}: {invalid_value}",
                    f"{hex_value}{header}: {valid_value}",
                    f"{hex_value}{header}: {invalid_value}"
                ))
            elif pos == 1:  # mutation + space before header name
                test_variations.append((
                    f"{mutation} {header}: {valid_value}",
                    f"{mutation} {header}: {invalid_value}",
                    f"{hex_value} {header}: {valid_value}",
                    f"{hex_value} {header}: {invalid_value}"
                ))
            elif pos == 2:  # after header name
                test_variations.append((
                    f"{header}{mutation}: {valid_value}",
                    f"{header}{mutation}: {invalid_value}",
                    f"{header}{hex_value}: {valid_value}",
                    f"{header}{hex_value}: {invalid_value}"
                ))
            elif pos == 3:  # space + mutation after header name
                test_variations.append((
                    f"{header} {mutation}: {valid_value}",
                    f"{header} {mutation}: {invalid_value}",
                    f"{header} {hex_value}: {valid_value}",
                    f"{header} {hex_value}: {invalid_value}"
                ))
            elif pos == 4:  # mutation + space after header name
                test_variations.append((
                    f"{header}{mutation} : {valid_value}",
                    f"{header}{mutation} : {invalid_value}",
                    f"{header}{hex_value} : {valid_value}",
                    f"{header}{hex_value} : {invalid_value}"
                ))
            elif pos == 5:  # space + mutation + space after header name
                test_variations.append((
                    f"{header} {mutation} : {valid_value}",
                    f"{header} {mutation} : {invalid_value}",
                    f"{header} {hex_value} : {valid_value}",
                    f"{header} {hex_value} : {invalid_value}"
                ))
            elif pos == 6:  # after colon + space
                test_variations.append((
                    f"{header}: {mutation}{valid_value}",
                    f"{header}: {mutation}{invalid_value}",
                    f"{header}: {hex_value}{valid_value}",
                    f"{header}: {hex_value}{invalid_value}"
                ))
            elif pos == 7:  # mutation + space after colon
                test_variations.append((
                    f"{header}:{mutation} {valid_value}",
                    f"{header}:{mutation} {invalid_value}",
                    f"{header}:{hex_value} {valid_value}",
                    f"{header}:{hex_value} {invalid_value}"
                ))
            elif pos == 8:  # space + mutation + space after colon
                test_variations.append((
                    f"{header}: {mutation} {valid_value}",
                    f"{header}: {mutation} {invalid_value}",
                    f"{header}: {hex_value} {valid_value}",
                    f"{header}: {hex_value} {invalid_value}"
                ))
            elif pos == 9:  # after value
                test_variations.append((
                    f"{header}: {valid_value}{mutation}",
                    f"{header}: {invalid_value}{mutation}",
                    f"{header}: {valid_value}{hex_value}",
                    f"{header}: {invalid_value}{hex_value}"
                ))
            elif pos == 10:  # space + mutation after value
                test_variations.append((
                    f"{header}: {valid_value} {mutation}",
                    f"{header}: {invalid_value} {mutation}",
                    f"{header}: {valid_value} {hex_value}",
                    f"{header}: {invalid_value} {hex_value}"
                ))

            # Test all variations for this position
            for mutated_header_valid, mutated_header_invalid, display_header_valid, display_header_invalid in test_variations:
                # Calculate padding for display headers to align output
                max_display_len = max(len(display_header_valid), len(display_header_invalid))
                
                # Make mutated valid requests
                mutated_valid = self.make_request_with_rate_limit_handling(header, mutated_header_valid, method)
                if mutated_valid.status_code == -1:
                    print(f"  Mutated Valid request failed ({mutated_valid.error}), retrying...")
                    mutated_valid = self.make_request_with_rate_limit_handling(header, mutated_header_valid, method)
                if mutated_valid.status_code == -1:
                    print(f"  Mutated Valid request failed ({mutated_valid.error}) twice, skipping this case.")
                    continue
                if mutated_valid.status_code == 0:
                    print(f"  Mutated Valid request timed out, retrying to confirm...")
                    mutated_valid = self.make_request_with_rate_limit_handling(header, mutated_header_valid, method)
                if mutated_valid.status_code == 0:
                    if self.skip_timeout:
                        print(f"  Mutated Valid request timed out ({mutated_valid.error}), skipping this case.")
                        continue
                    print(f"  Mutated Valid request timed out ({mutated_valid.error}), confirmed.")
                print(f"  Mutated Valid   ({display_header_valid}){' ' * (max_display_len - len(display_header_valid))}: Status={mutated_valid.status_code:<4} | Body Lines={mutated_valid.body_lines:<4} | Body Length={mutated_valid.body_length:<6} | Headers Lines={mutated_valid.headers_lines:<3} | Headers Length={mutated_valid.headers_length:<4}")

                # Make mutated invalid requests
                mutated_invalid = self.make_request_with_rate_limit_handling(header, mutated_header_invalid, method)
                if mutated_invalid.status_code == -1:
                    print(f"  Mutated Invalid request failed ({mutated_invalid.error}), retrying...")
                    mutated_invalid = self.make_request_with_rate_limit_handling(header, mutated_header_invalid, method)
                if mutated_invalid.status_code == -1:
                    print(f"  Mutated Invalid request failed ({mutated_invalid.error}) twice, skipping this case.")
                    continue
                if mutated_invalid.status_code == 0:
                    print(f"  Mutated Invalid request timed out ({mutated_invalid.error}), retrying to confirm...")
                    mutated_invalid = self.make_request_with_rate_limit_handling(header, mutated_header_invalid, method)
                if mutated_invalid.status_code == 0:
                    if self.skip_timeout:
                        print(f"  Mutated Invalid request timed out ({mutated_invalid.error}), skipping this case.")
                        continue
                    print(f"  Mutated Invalid request timed out ({mutated_invalid.error}), confirmed.")
                print(f"  Mutated Invalid ({display_header_invalid}){' ' * (max_display_len - len(display_header_invalid))}: Status={mutated_invalid.status_code:<4} | Body Lines={mutated_invalid.body_lines:<4} | Body Length={mutated_invalid.body_length:<6} | Headers Lines={mutated_invalid.headers_lines:<3} | Headers Length={mutated_invalid.headers_length:<4}")
                
                # Check for discrepancy using body and headers lines and lengths with deviation
                def within_deviation(val1, val2, dev):
                    """Check if val1 and val2 are within dev% of each other based on the larger value"""
                    if val1 == val2:
                        return True
                    max_val = max(abs(val1), abs(val2))
                    if max_val == 0:
                        return True
                    percentage_diff = (abs(val1 - val2) / max_val) * 100
                    return percentage_diff <= dev

                baseline_same_status_code = (
                    baseline_valid.status_code == mutated_valid.status_code
                )

                mutated_different_status_code = (
                    (baseline_invalid.status_code != mutated_invalid.status_code) and
                    (baseline_valid.status_code != mutated_invalid.status_code)
                )

                baseline_same_body_lines = (
                    baseline_valid.status_code == mutated_valid.status_code and
                    baseline_valid.body_lines == mutated_valid.body_lines
                )

                mutated_different_body_lines = (
                    (baseline_invalid.body_lines != mutated_invalid.body_lines) and
                    (baseline_valid.body_lines != mutated_invalid.body_lines)
                )

                baseline_same_headers_lines = (
                    baseline_valid.status_code == mutated_valid.status_code and
                    baseline_valid.headers_lines == mutated_valid.headers_lines
                )

                mutated_different_headers_lines = (
                    (baseline_invalid.headers_lines != mutated_invalid.headers_lines) and
                    (baseline_valid.headers_lines != mutated_invalid.headers_lines)
                )

                baseline_same_body_length = (
                    baseline_valid.status_code == mutated_valid.status_code and
                    within_deviation(baseline_valid.body_length, mutated_valid.body_length, deviation)
                )

                mutated_different_body_length = (
                    (not within_deviation(baseline_invalid.body_length, mutated_invalid.body_length, deviation)) and
                    (not within_deviation(baseline_valid.body_length, mutated_invalid.body_length, deviation))
                )

                baseline_same_headers_length = (
                    baseline_valid.status_code == mutated_valid.status_code and
                    within_deviation(baseline_valid.headers_length, mutated_valid.headers_length, deviation)
                )

                mutated_different_headers_length = (
                    (not within_deviation(baseline_invalid.headers_length, mutated_invalid.headers_length, deviation)) and
                    (not within_deviation(baseline_valid.headers_length, mutated_invalid.headers_length, deviation))
                )

                # Helper function to confirm discrepancy by retesting
                def confirm_mutation_discrepancy(discrepancy_type, method):
                    """Confirm mutation discrepancy by retesting the same requests"""
                    print(f"  ↻ Confirming {discrepancy_type} discrepancy by retesting...")
                    
                    # Retest mutated valid request
                    confirm_valid = self.make_request_with_rate_limit_handling(header, mutated_header_valid, method)
                    if confirm_valid.status_code == -1:
                        print(f"    Confirmation Valid request failed, skipping confirmation")
                        return False
                    
                    # Retest mutated invalid request  
                    confirm_invalid = self.make_request_with_rate_limit_handling(header, mutated_header_invalid, method)
                    if confirm_invalid.status_code == -1:
                        print(f"    Confirmation Invalid request failed, skipping confirmation")
                        return False
                    
                    # Print confirmation results
                    print(f"    Mutated Valid   ({display_header_valid}){' ' * (max_display_len - len(display_header_valid))}: Status={confirm_valid.status_code:<4} | Body Lines={confirm_valid.body_lines:<4} | Body Length={confirm_valid.body_length:<6} | Headers Lines={confirm_valid.headers_lines:<3} | Headers Length={confirm_valid.headers_length:<4}")
                    print(f"    Mutated Invalid ({display_header_invalid}){' ' * (max_display_len - len(display_header_invalid))}: Status={confirm_invalid.status_code:<4} | Body Lines={confirm_invalid.body_lines:<4} | Body Length={confirm_invalid.body_length:<6} | Headers Lines={confirm_invalid.headers_lines:<3} | Headers Length={confirm_invalid.headers_length:<4}")
                    
                    # Check the same criteria that triggered the original discrepancy
                    if discrepancy_type == 'status_code':
                        baseline_same = (baseline_valid.status_code == confirm_valid.status_code)
                        mutated_different = ((baseline_invalid.status_code != confirm_invalid.status_code) and
                                           (baseline_valid.status_code != confirm_invalid.status_code))
                        return baseline_same and mutated_different
                    
                    elif discrepancy_type == 'body_lines':
                        baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                                       baseline_valid.body_lines == confirm_valid.body_lines)
                        mutated_different = ((baseline_invalid.body_lines != confirm_invalid.body_lines) and
                                           (baseline_valid.body_lines != confirm_invalid.body_lines))
                        return baseline_same and mutated_different
                    
                    elif discrepancy_type == 'headers_lines':
                        baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                                       baseline_valid.headers_lines == confirm_valid.headers_lines)
                        mutated_different = ((baseline_invalid.headers_lines != confirm_invalid.headers_lines) and
                                           (baseline_valid.headers_lines != confirm_invalid.headers_lines))
                        return baseline_same and mutated_different
                    
                    elif discrepancy_type == 'body_length':
                        baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                                       within_deviation(baseline_valid.body_length, confirm_valid.body_length, deviation))
                        mutated_different = ((not within_deviation(baseline_invalid.body_length, confirm_invalid.body_length, deviation)) and
                                           (not within_deviation(baseline_valid.body_length, confirm_invalid.body_length, deviation)))
                        return baseline_same and mutated_different
                    
                    elif discrepancy_type == 'headers_length':
                        baseline_same = (baseline_valid.status_code == confirm_valid.status_code and
                                       within_deviation(baseline_valid.headers_length, confirm_valid.headers_length, deviation))
                        mutated_different = ((not within_deviation(baseline_invalid.headers_length, confirm_invalid.headers_length, deviation)) and
                                           (not within_deviation(baseline_valid.headers_length, confirm_invalid.headers_length, deviation)))
                        return baseline_same and mutated_different
                    
                    return False

                # Check order: status_code, body_lines, headers_lines, body_length, headers_length
                if baseline_same_status_code and mutated_different_status_code:
                    # Confirm discrepancy if confirmation is enabled
                    confirmed = True
                    if confirm:
                        confirmed = confirm_mutation_discrepancy('status_code', method)
                        if not confirmed:
                            print(f"  ⚠ Initial status_code discrepancy could not be confirmed, skipping")
                            print(f"  ✓ No confirmed discrepancy detected")
                            print()
                            continue
                        else:
                            print(f"  ✓ Status_code discrepancy confirmed!")
                    
                    if confirmed:
                        finding = {
                            'case': case,
                            'position': pos,
                            'position_description': pos_desc,
                            'mutation': hex_value,
                            'mutation_name': name_part,
                            'header': header,
                            'method': method,
                            'valid_value': valid_value,
                            'invalid_value': invalid_value,
                            'discrepancy_type': 'status_code',
                            'baseline_valid': (baseline_valid.status_code),
                            'baseline_invalid': (baseline_invalid.status_code),
                            'mutated_valid': (mutated_valid.status_code),
                            'mutated_invalid': (mutated_invalid.status_code)
                        }
                        findings.append(finding)
                        print(f"\n☢ WARNING! {method} | {header} | V:{valid_value} | I:{invalid_value} | {hex_value} ({name_part}) | {pos_desc} | STATUS CODE | BV {baseline_valid.status_code} BI {baseline_invalid.status_code} | MV {mutated_valid.status_code} MI {mutated_invalid.status_code}")
                        print(f"  Baseline valid ({baseline_valid.status_code}) matches mutated valid ({mutated_valid.status_code})")
                        print(f"  BUT baseline invalid ({baseline_invalid.status_code}) differs from mutated invalid ({mutated_invalid.status_code})")
                        print(f"  AND baseline valid ({baseline_valid.status_code}) differs from mutated invalid ({mutated_invalid.status_code})")
                        print(f"  This suggests the mutation affects header parsing differently on {self.url}!")
                        if quit_on_first:
                            print(f"\nExiting on first discrepancy detected.")
                            return findings                
                elif baseline_same_body_lines and mutated_different_body_lines:
                    # Confirm discrepancy if confirmation is enabled
                    confirmed = True
                    if confirm:
                        confirmed = confirm_mutation_discrepancy('body_lines', method)
                        if not confirmed:
                            print(f"  ⚠ Initial body_lines discrepancy could not be confirmed, skipping")
                            print(f"  ✓ No confirmed discrepancy detected")
                            print()
                            continue
                        else:
                            print(f"  ✓ Body_lines discrepancy confirmed!")
                    
                    if confirmed:
                        finding = {
                            'case': case,
                            'position': pos,
                            'position_description': pos_desc,
                            'mutation': hex_value,
                            'mutation_name': name_part,
                            'header': header,
                            'method': method,
                            'valid_value': valid_value,
                            'invalid_value': invalid_value,
                            'discrepancy_type': 'body_lines',
                            'baseline_valid': (baseline_valid.status_code, baseline_valid.body_lines),
                            'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.body_lines),
                            'mutated_valid': (mutated_valid.status_code, mutated_valid.body_lines),
                            'mutated_invalid': (mutated_invalid.status_code, mutated_invalid.body_lines)
                        }
                        findings.append(finding)
                        body_lines_diff = abs(baseline_invalid.body_lines - mutated_invalid.body_lines)
                        print(f"\n☢ WARNING! {method} | {header} | V:{valid_value} | I:{invalid_value} | {hex_value} ({name_part}) | {pos_desc} | BODY LINES ({body_lines_diff}) | BV {baseline_valid.status_code}/{baseline_valid.body_lines} BI {baseline_invalid.status_code}/{baseline_invalid.body_lines} | MV {mutated_valid.status_code}/{mutated_valid.body_lines} MI {mutated_invalid.status_code}/{mutated_invalid.body_lines}")
                        print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.body_lines}) matches mutated valid ({mutated_valid.status_code}/{mutated_valid.body_lines})")
                        print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.body_lines}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.body_lines})")
                        print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.body_lines}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.body_lines})")
                        print(f"  This suggests the mutation affects header parsing differently on {self.url}!")
                        if quit_on_first:
                            print(f"\nExiting on first discrepancy detected.")
                            return findings
                elif baseline_same_headers_lines and mutated_different_headers_lines:
                    # Confirm discrepancy if confirmation is enabled
                    confirmed = True
                    if confirm:
                        confirmed = confirm_mutation_discrepancy('headers_lines', method)
                        if not confirmed:
                            print(f"  ⚠ Initial headers_lines discrepancy could not be confirmed, skipping")
                            print(f"  ✓ No confirmed discrepancy detected")
                            print()
                            continue
                        else:
                            print(f"  ✓ Headers_lines discrepancy confirmed!")
                    
                    if confirmed:
                        finding = {
                            'case': case,
                            'position': pos,
                            'position_description': pos_desc,
                            'mutation': hex_value,
                            'mutation_name': name_part,
                            'header': header,
                            'method': method,
                            'valid_value': valid_value,
                            'invalid_value': invalid_value,
                            'discrepancy_type': 'headers_lines',
                            'baseline_valid': (baseline_valid.status_code, baseline_valid.headers_lines),
                            'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.headers_lines),
                            'mutated_valid': (mutated_valid.status_code, mutated_valid.headers_lines),
                            'mutated_invalid': (mutated_invalid.status_code, mutated_invalid.headers_lines)
                        }
                        findings.append(finding)
                        headers_lines_diff = abs(baseline_invalid.headers_lines - mutated_invalid.headers_lines)
                        print(f"\n☢ WARNING! {method} | {header} | V:{valid_value} | I:{invalid_value} | {hex_value} ({name_part}) | {pos_desc} | HEADERS LINES ({headers_lines_diff}) | BV {baseline_valid.status_code}/{baseline_valid.headers_lines} BI {baseline_invalid.status_code}/{baseline_invalid.headers_lines} | MV {mutated_valid.status_code}/{mutated_valid.headers_lines} MI {mutated_invalid.status_code}/{mutated_invalid.headers_lines}")
                        print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_lines}) matches mutated valid ({mutated_valid.status_code}/{mutated_valid.headers_lines})")
                        print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.headers_lines}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.headers_lines})")
                        print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_lines}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.headers_lines})")
                        print(f"  This suggests the mutation affects header parsing differently on {self.url}!")
                        if quit_on_first:
                            print(f"\nExiting on first discrepancy detected.")
                            return findings
                elif baseline_same_body_length and mutated_different_body_length:
                    # Confirm discrepancy if confirmation is enabled
                    confirmed = True
                    if confirm:
                        confirmed = confirm_mutation_discrepancy('body_length', method)
                        if not confirmed:
                            print(f"  ⚠ Initial body_length discrepancy could not be confirmed, skipping")
                            print(f"  ✓ No confirmed discrepancy detected")
                            print()
                            continue
                        else:
                            print(f"  ✓ Body_length discrepancy confirmed!")
                    
                    if confirmed:
                        # Calculate percentage differences for body length
                        max_val_bv_mv = max(abs(baseline_valid.body_length), abs(mutated_valid.body_length))
                        diff_bv_mv = (abs(baseline_valid.body_length - mutated_valid.body_length) / max_val_bv_mv * 100) if max_val_bv_mv > 0 else 0
                        
                        max_val_bi_mi = max(abs(baseline_invalid.body_length), abs(mutated_invalid.body_length))
                        diff_bi_mi = (abs(baseline_invalid.body_length - mutated_invalid.body_length) / max_val_bi_mi * 100) if max_val_bi_mi > 0 else 0
                        
                        max_val_bv_mi = max(abs(baseline_valid.body_length), abs(mutated_invalid.body_length))
                        diff_bv_mi = (abs(baseline_valid.body_length - mutated_invalid.body_length) / max_val_bv_mi * 100) if max_val_bv_mi > 0 else 0
                        
                        finding = {
                            'case': case,
                            'position': pos,
                            'position_description': pos_desc,
                            'mutation': hex_value,
                            'mutation_name': name_part,
                            'header': header,
                            'method': method,
                            'valid_value': valid_value,
                            'invalid_value': invalid_value,
                            'discrepancy_type': 'body_length',
                            'baseline_valid': (baseline_valid.status_code, baseline_valid.body_length),
                            'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.body_length),
                            'mutated_valid': (mutated_valid.status_code, mutated_valid.body_length),
                            'mutated_invalid': (mutated_invalid.status_code, mutated_invalid.body_length)
                        }
                        findings.append(finding)
                        print(f"\n☢ WARNING! {method} | {header} | V:{valid_value} | I:{invalid_value} | {hex_value} ({name_part}) | {pos_desc} | BODY LENGTH | {deviation}% deviation | BV {baseline_valid.status_code}/{baseline_valid.body_length} BI {baseline_invalid.status_code}/{baseline_invalid.body_length} | MV {mutated_valid.status_code}/{mutated_valid.body_length} MI {mutated_invalid.status_code}/{mutated_invalid.body_length}")
                        print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.body_length}) matches mutated valid ({mutated_valid.status_code}/{mutated_valid.body_length}) - Difference: {diff_bv_mv:.2f}%")
                        print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.body_length}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.body_length}) - Difference: {diff_bi_mi:.2f}%")
                        print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.body_length}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.body_length}) - Difference: {diff_bv_mi:.2f}%")
                        print(f"  AND the deviation used during comparison of the body lengths was {deviation}%.")
                        print(f"  This suggests the mutation affects header parsing differently on {self.url}!")
                        if quit_on_first:
                            print(f"\nExiting on first discrepancy detected.")
                            return findings
                elif baseline_same_headers_length and mutated_different_headers_length:
                    # Confirm discrepancy if confirmation is enabled
                    confirmed = True
                    if confirm:
                        confirmed = confirm_mutation_discrepancy('headers_length', method)
                        if not confirmed:
                            print(f"  ⚠ Initial headers_length discrepancy could not be confirmed, skipping")
                            print(f"  ✓ No confirmed discrepancy detected")
                            print()
                            continue
                        else:
                            print(f"  ✓ Headers_length discrepancy confirmed!")
                    
                    if confirmed:
                        # Calculate percentage differences for headers length
                        max_val_bv_mv = max(abs(baseline_valid.headers_length), abs(mutated_valid.headers_length))
                        diff_bv_mv = (abs(baseline_valid.headers_length - mutated_valid.headers_length) / max_val_bv_mv * 100) if max_val_bv_mv > 0 else 0
                        
                        max_val_bi_mi = max(abs(baseline_invalid.headers_length), abs(mutated_invalid.headers_length))
                        diff_bi_mi = (abs(baseline_invalid.headers_length - mutated_invalid.headers_length) / max_val_bi_mi * 100) if max_val_bi_mi > 0 else 0
                        
                        max_val_bv_mi = max(abs(baseline_valid.headers_length), abs(mutated_invalid.headers_length))
                        diff_bv_mi = (abs(baseline_valid.headers_length - mutated_invalid.headers_length) / max_val_bv_mi * 100) if max_val_bv_mi > 0 else 0
                        
                        finding = {
                            'case': case,
                            'position': pos,
                            'position_description': pos_desc,
                            'mutation': hex_value,
                            'mutation_name': name_part,
                            'header': header,
                            'method': method,
                            'valid_value': valid_value,
                            'invalid_value': invalid_value,
                            'discrepancy_type': 'headers_length',
                            'baseline_valid': (baseline_valid.status_code, baseline_valid.headers_length),
                            'baseline_invalid': (baseline_invalid.status_code, baseline_invalid.headers_length),
                            'mutated_valid': (mutated_valid.status_code, mutated_valid.headers_length),
                            'mutated_invalid': (mutated_invalid.status_code, mutated_invalid.headers_length)
                        }
                        findings.append(finding)
                        print(f"\n☢ WARNING! {method} | {header} | V:{valid_value} | I:{invalid_value} | {hex_value} ({name_part}) | {pos_desc} | HEADERS LENGTH | {deviation}% deviation | BV {baseline_valid.status_code}/{baseline_valid.headers_length} BI {baseline_invalid.status_code}/{baseline_invalid.headers_length} | MV {mutated_valid.status_code}/{mutated_valid.headers_length} MI {mutated_invalid.status_code}/{mutated_invalid.headers_length}")
                        print(f"  Baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_length}) matches mutated valid ({mutated_valid.status_code}/{mutated_valid.headers_length}) - Difference: {diff_bv_mv:.2f}%")
                        print(f"  BUT baseline invalid ({baseline_invalid.status_code}/{baseline_invalid.headers_length}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.headers_length}) - Difference: {diff_bi_mi:.2f}%")
                        print(f"  AND baseline valid ({baseline_valid.status_code}/{baseline_valid.headers_length}) differs from mutated invalid ({mutated_invalid.status_code}/{mutated_invalid.headers_length}) - Difference: {diff_bv_mi:.2f}%")
                        print(f"  AND the deviation used during comparison of the headers lengths was {deviation}%.")
                        print(f"  This suggests the mutation affects header parsing differently on {self.url}!")
                        if quit_on_first:
                            print(f"\nExiting on first discrepancy detected.")
                            return findings
                else:
                    print(f"  ✓ No discrepancy detected")

                print()
        
        return findings


def load_config_file(config_path: str, skip_transformations: bool, skip_mutations: bool) -> Tuple[List[Tuple], List[Tuple], List[Tuple], object]:
    """Load and validate configuration file (Python format)"""
    if not os.path.exists(config_path):
        print(f"✗ Configuration file not found: {config_path}")
        sys.exit(1)
    
    try:
        # Load Python configuration file
        spec = importlib.util.spec_from_file_location("config", config_path)
        if spec is not None and spec.loader is not None:
            config_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config_module)
        else:
            raise ImportError("Module spec or loader is None")
    except Exception as e:
        print(f"✗ Error loading configuration file: {e}")
        sys.exit(1)
    
    # Validate that at least one configuration section exists
    has_configurations = hasattr(config_module, 'test_configurations')
    has_mutations = hasattr(config_module, 'test_mutations')
    has_transformations = hasattr(config_module, 'test_transformations')
    
    if not (has_configurations or has_mutations or has_transformations):
        print("✗ Configuration file must contain at least one of: 'test_configurations', 'test_mutations', or 'test_transformations'")
        sys.exit(1)
    
    # Load test_configurations (use hardcoded if missing)
    test_configurations = []
    if has_configurations:
        for i, item in enumerate(config_module.test_configurations):
            if not isinstance(item, (list, tuple)) or len(item) != 4:
                print(f"✗ test_configurations[{i}] must be a list/tuple with 4 elements: (method, header, valid_value, invalid_value)")
                sys.exit(1)
            
            method, header, valid_value, invalid_value = item
            if not all(isinstance(x, str) for x in [method, header, valid_value, invalid_value]):
                print(f"✗ test_configurations[{i}] all elements must be strings")
                sys.exit(1)
                
            test_configurations.append((method, header, valid_value, invalid_value))
    else:
        # Use hardcoded defaults
        test_configurations = DEFAULT_TEST_CONFIGURATIONS.copy()
    
    # Load test_mutations (use hardcoded if missing or skipped)
    test_mutations = []
    if not skip_mutations:
        if has_mutations:
            for i, item in enumerate(config_module.test_mutations):
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    print(f"✗ test_mutations[{i}] must be a list/tuple with 2 elements: (character, description)")
                    sys.exit(1)
                
                char, desc = item
                if not isinstance(char, str) or not isinstance(desc, str):
                    print(f"✗ test_mutations[{i}] both elements must be strings")
                    sys.exit(1)
                
                test_mutations.append((char, desc))
        else:
            # Use hardcoded defaults
            test_mutations = DEFAULT_TEST_MUTATIONS.copy()
    
    # Load test_transformations (use hardcoded if missing or skipped)
    test_transformations = []
    if not skip_transformations:
        if has_transformations:
            for i, item in enumerate(config_module.test_transformations):
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    print(f"✗ test_transformations[{i}] must be a list/tuple with 2 elements: (function_name, description)")
                    sys.exit(1)
                
                function_name, desc = item
                if not isinstance(function_name, str) or not isinstance(desc, str):
                    print(f"✗ test_transformations[{i}] both elements must be strings")
                    sys.exit(1)
                
                # Check if function exists in config module or is a built-in function
                func = None
                is_builtin = False
                
                # List of built-in transformation functions
                builtin_functions = ['hyphen_to_underscore', 'case_swap', 'unicode_mapping']
                
                if hasattr(config_module, function_name):
                    # Function exists in config module
                    func = getattr(config_module, function_name)
                    if not callable(func):
                        print(f"✗ '{function_name}' is not a callable function")
                        sys.exit(1)
                elif function_name in builtin_functions:
                    # Function is a built-in function - we'll validate it exists in the detector class later
                    is_builtin = True
                else:
                    print(f"✗ Function '{function_name}' not found in config file or built-in functions")
                    sys.exit(1)
                
                # Validate function signature for custom functions (built-ins are pre-validated)
                if not is_builtin and func is not None:
                    import inspect
                    try:
                        sig = inspect.signature(func)
                        params = list(sig.parameters.values())
                        if len(params) != 1:
                            print(f"✗ Function '{function_name}' must accept exactly one parameter")
                            sys.exit(1)
                    except Exception as e:
                        print(f"✗ Error inspecting function '{function_name}': {e}")
                        sys.exit(1)
                
                test_transformations.append((function_name, desc))
        else:
            # Use hardcoded defaults
            test_transformations = DEFAULT_TEST_TRANSFORMATIONS.copy()
    
    return test_configurations, test_mutations, test_transformations, config_module


def main():
    parser = argparse.ArgumentParser(
        description="Detect header parsing discrepancies across proxy chains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  hpdd https://example.com
  hpdd https://example.com -t 15
  hpdd https://example.com -u "Custom-Agent/1.0"
  hpdd https://example.com -q
  hpdd https://example.com -m POST
  hpdd https://example.com -c config.py
  hpdd https://example.com -st
  hpdd https://example.com -sm
  hpdd https://example.com --timeout 15 --quit-on-first
        """
    )
    
    parser.add_argument('url', help='Target URL to test.')
    parser.add_argument('-n', '--connection_header', default='close', help='Value for Connection header (default: close).')
    parser.add_argument('-s', '--upgrade-https', action='store_true', help='Upgrade URL to https if the same subdomain accepts https requests.')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10).')
    parser.add_argument('-u', '--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36', help='User-Agent string (default: Chrome 138).')
    parser.add_argument('-q', '--quit-on-first', action='store_true', help='Exit immediately when the first discrepancy is found (default: false).')
    parser.add_argument('-m', '--method', type=str, help='HTTP method to use for all requests, overriding per-header configuration (e.g., GET, POST, PUT).')
    parser.add_argument('-c', '--config-file', type=str, help='Path to Python configuration file containing required test_configurations, test_transformations and test_mutations variables.')
    parser.add_argument('-st', '--skip-transformations', action='store_true', help='Skip transformation tests (cannot be used with --skip-mutations).')
    parser.add_argument('-sm', '--skip-mutations', action='store_true', help='Skip mutation tests (cannot be used with --skip-transformations).')
    parser.add_argument('-e', '--deviation', type=int, default=20, help='Allowed deviation percentage for response body/headers length comparisons (default: 20).')
    parser.add_argument('-d', '--debug', action='store_true', help='Print raw HTTP request for debugging (default: false).')
    parser.add_argument('-k', '--confirm', action='store_true', help='Confirm discrepancies by retesting the same requests before reporting (default: false).')
    parser.add_argument('-so', '--skip-timeout', action='store_true', help='Skip tests when timeout occurs, treating timeouts the same as failed requests (default: false).')
    
    args = parser.parse_args()

    # Show help and exit if URL is not provided
    if not getattr(args, 'url', None):
        parser.print_help()
        sys.exit(1)
    
    # Validate that user cannot skip both transformations and mutations
    if args.skip_transformations and args.skip_mutations:
        print("✗ Error: Cannot skip both transformations and mutations. At least one test type must be enabled.")
        parser.print_help()
        sys.exit(1)
    
    # Print ASCII art banner with version
    print(f"┓┏┏┓┳┓┳┓")
    print(f"┣┫┃┃┃┃┃┃")
    print(f"┛┗┣┛┻┛┻┛ v{VERSION}")
    print("Header Parsing Discrepancy Detector")
    print("\u2500" * 80)
    
    # Optionally upgrade to https if requested
    if args.upgrade_https:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(args.url)
        if parsed.scheme == 'http':
            https_url = urlunparse(parsed._replace(scheme='https'))
            try:
                resp = requests.get(https_url, timeout=args.timeout, verify=False)
                print(f"Upgrading {args.url} to {https_url} (Status Code {resp.status_code})")
                args.url = https_url
            except Exception as e:
                print(f"HTTPS not available for {https_url} ({e}), using original URL.")
        print("\u2500" * 80)

    # Load configurations - either from file or use hardcoded defaults
    config_module = None
    if args.config_file:
        test_configurations, test_mutations, test_transformations, config_module = load_config_file(args.config_file, args.skip_transformations, args.skip_mutations)
    else:
        # Use hardcoded defaults
        test_configurations = DEFAULT_TEST_CONFIGURATIONS.copy()
        test_mutations = [] if args.skip_mutations else DEFAULT_TEST_MUTATIONS.copy()
        test_transformations = [] if args.skip_transformations else DEFAULT_TEST_TRANSFORMATIONS.copy()

    print(f"Target URL        : {args.url}")
    print(f"Timeout           : {args.timeout}s")
    print(f"User-Agent        : {args.user_agent}")
    print(f"Confirm           : {args.confirm}")
    print(f"Debug             : {args.debug}")
    print(f"Upgrade HTTPS     : {args.upgrade_https}")
    print(f"Connection Header : {args.connection_header}")
    print(f"Quit on First     : {args.quit_on_first}")
    print(f"Skip Timeout      : {args.skip_timeout}")
    if args.method:
        print(f"Method Override   : {args.method}")
    if args.config_file:
        print(f"Config File       : {args.config_file}")
    else:
        print(f"Config Source     : Hardcoded defaults")
    print(f"Configurations    : {len(test_configurations)}")
    print(f"Transformations   : {len(test_transformations)}{' (SKIPPED)' if args.skip_transformations else ''}")
    print(f"Mutations         : {len(test_mutations)}{' (SKIPPED)' if args.skip_mutations else ''}")
    print(f"Deviation         : {args.deviation}%")
    print("\u2500" * 80)
    print()
    
    # Initialize detector
    url = args.url
    if isinstance(url, bytes):
        url = url.decode("utf-8")
    detector = HeaderDiscrepancyDetector(url, args.timeout, args.user_agent, args.connection_header, args.debug, args.skip_timeout)
    
    # Dynamically inject custom transformation functions from config
    if config_module is not None:
        builtin_functions = ['hyphen_to_underscore', 'case_swap', 'unicode_mapping']
        for function_name, description in test_transformations:
            if hasattr(config_module, function_name):
                custom_func = getattr(config_module, function_name)
                # Add the custom function as a method to the detector instance
                setattr(detector, function_name, custom_func)
    
    all_findings = []
    
    # Test all combinations of headers and mutations
    for method, header, valid_value, invalid_value in test_configurations:
        # Use method override if provided, otherwise use per-header method
        test_method = args.method if args.method else method
        
        print("\u2500" * 80)
        print(f"Testing Header : {header}")
        print(f"Method         : {test_method}")
        print(f"Valid Value    : {valid_value}")
        print(f"Invalid Value  : {invalid_value}")
        print("\u2500" * 80)
        
        # Make baseline requests once per header
        print("Baseline requests:")
        baseline_valid = detector.make_request_with_rate_limit_handling(header, f"{header}: {valid_value}", test_method)
        if baseline_valid.status_code == -1:
            print(f"  Baseline Valid request failed ({baseline_valid.error}), retrying...")
            baseline_valid = detector.make_request_with_rate_limit_handling(header, f"{header}: {valid_value}", test_method)
        if baseline_valid.status_code == -1:
            print(f"  Baseline Valid request failed twice ({baseline_valid.error}), skipping this header.")
            print()
            continue
        if baseline_valid.status_code == 0:
            print(f"  Baseline Valid request timed out ({baseline_valid.error}), retrying...")
            baseline_valid = detector.make_request_with_rate_limit_handling(header, f"{header}: {valid_value}", test_method)
        if baseline_valid.status_code == 0:
            if args.skip_timeout:
                print(f"  Baseline Valid request timed out ({baseline_valid.error}), skipping this header.")
            else:
                print(f"  Baseline Valid request timed out ({baseline_valid.error}), confirmed. Skipping this header.")
            print()
            continue
        
        # Calculate padding for header values to align output
        max_header_len = max(len(f"{header}: {valid_value}"), len(f"{header}: {invalid_value}"))
        
        print(f"  Baseline Valid   ({header}: {valid_value}){' ' * (max_header_len - len(f'{header}: {valid_value}'))}: Status={baseline_valid.status_code:<4} | Body Lines={baseline_valid.body_lines:<4} | Body Length={baseline_valid.body_length:<6} | Headers Lines={baseline_valid.headers_lines:<3} | Headers Length={baseline_valid.headers_length:<4}")
        
        baseline_invalid = detector.make_request_with_rate_limit_handling(header, f"{header}: {invalid_value}", test_method)
        if baseline_invalid.status_code == -1:
            print(f"  Baseline Invalid request failed ({baseline_invalid.error}), retrying...")
            baseline_invalid = detector.make_request_with_rate_limit_handling(header, f"{header}: {invalid_value}", test_method)
        if baseline_invalid.status_code == -1:
            print(f"  Baseline Invalid request failed twice ({baseline_invalid.error}), skipping this header.")
            print()
            continue
        if baseline_invalid.status_code == 0:
            print(f"  Baseline Invalid request timed out ({baseline_invalid.error}), retrying to confirm...")
            baseline_invalid = detector.make_request_with_rate_limit_handling(header, f"{header}: {invalid_value}", test_method)
        if baseline_invalid.status_code == 0:
            if args.skip_timeout:
                print(f"  Baseline Invalid request timed out ({baseline_invalid.error}), skipping this header.")
                print()
                continue
            print(f"  Baseline Invalid request timed out ({baseline_invalid.error}), confirmed.")
        print(f"  Baseline Invalid ({header}: {invalid_value}){' ' * (max_header_len - len(f'{header}: {invalid_value}'))}: Status={baseline_invalid.status_code:<4} | Body Lines={baseline_invalid.body_lines:<4} | Body Length={baseline_invalid.body_length:<6} | Headers Lines={baseline_invalid.headers_lines:<3} | Headers Length={baseline_invalid.headers_length:<4}")
        print()
        
        # Test transformations (unless skipped)
        if not args.skip_transformations:
            for function_name, transformation_description in test_transformations:
                # Run transformation tests for this combination
                findings = detector.test_header_discrepancy_transformations(
                    header,
                    valid_value,
                    invalid_value,
                    function_name,
                    transformation_description,
                    baseline_valid,
                    baseline_invalid,
                    args.quit_on_first,
                    test_method,
                    args.deviation,
                    args.confirm
                )
                
                if findings:
                    all_findings.extend(findings)
                    
                    # Check if we should quit on first discrepancy
                    if args.quit_on_first:
                        return 1
        
        # Test mutations (unless skipped)
        if not args.skip_mutations:
            for mutation_char, mutation_name in test_mutations:
                # Run tests for this combination
                findings = detector.test_header_discrepancy_mutations(
                    header, 
                    valid_value, 
                    invalid_value, 
                    mutation_char,
                    mutation_name,
                    baseline_valid,
                    baseline_invalid,
                    args.quit_on_first,
                    test_method,
                    args.deviation,
                    args.confirm
                )
                
                if findings:
                    all_findings.extend(findings)
                    
                    # Check if we should quit on first discrepancy
                    if args.quit_on_first:
                        return 1
    
    # Report final results
    print("\n" + "\u2500" * 80)
    print(f"FINAL RESULTS {url}")
    print("\u2500" * 80)
    
    if all_findings:
        print(f"☢ {len(all_findings)} TOTAL DISCREPANCY(IES) DETECTED!")
        print()
        
        for i, finding in enumerate(all_findings, 1):
            print(f"Finding #{i}")
            
            # Handle both mutation and transformation findings
            if 'position_description' in finding:
                # Mutation finding
                print(f"  Type          : Mutation")
                print(f"  Method        : {finding['method']}")
                print(f"  Header        : {finding['header']}")
                print(f"  Valid Value   : {finding['valid_value']}")
                print(f"  Invalid Value : {finding['invalid_value']}")
                print(f"  Position      : {finding['position_description']}")
                print(f"  Mutation      : {finding['mutation']} ({finding['mutation_name']})")
                print(f"  Discrepancy   : {finding['discrepancy_type']}")
            elif 'transformation' in finding:
                # Transformation finding
                print(f"  Type           : Transformation")
                print(f"  Method         : {finding['method']}")
                print(f"  Header         : {finding['original_header']}")
                print(f"  Valid Value    : {finding['valid_value']}")
                print(f"  Invalid Value  : {finding['invalid_value']}")
                print(f"  Transformation : {finding['transformation_description']}")
                print(f"  Transformed    : {finding['transformed_header']}")
                print(f"  Discrepancy    : {finding['discrepancy_type']}")
            
            print()
            
        return 1  # Exit with error code to indicate findings
    else:
        print("✓ No header parsing discrepancies detected across all test combinations.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
