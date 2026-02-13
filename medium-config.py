#!/usr/bin/env python3
"""
Sample configuration file for header-discrepancy.py

This file demonstrates the format for test configurations, transformations and mutation characters.
Users can copy this format and modify it as needed.
"""

# Test configurations: (method, header, valid_value, invalid_value)
test_configurations = [
    ("POST", "Content-Length", "0", "z"),
    ("GET", "Host", "example.com", "invalid@example#com"),
    ("POST", "Transfer-Encoding", "chunked", "invalid@ value# test$"),
    ("GET", "X-Forwarded-For", "127.0.0.1", "invalid@ip#address"),
    ("GET", "X-Forwarded-Host", "example.com", "invalid@example#com"),
    ("POST", "Expect", "100-continue", "invalid@ value# test$"),
    ("GET", "Connection", "keep-alive", "invalid@ value# test$"),
    ("GET", "Authorization", "Bearer token123", "Bearer invalid@ token! #"),
    ("POST", "Content-Type", "application/json", "invalid@ type# test$"),
    ("GET", "Forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43", "invalid@ value# test$"),
    ("GET", "Keep-Alive", "timeout=5, max=200", "invalid@ value# test$"),
    ("OPTIONS", "Max-Forwards", "10", "invalid@ value# test$"),
    ("GET", "Range", "bytes=0-1", "invalid@ value# test$")
]

# Custom transformation function
def add_x_prefix(header):
    """Add X- prefix to the header name"""
    return f"X-{header}"

# Transformation functions: (function_name, description)
test_transformations = [
    ("hyphen_to_underscore", "Replace hyphens with underscores (Header-Name → Header_Name)"),
    ("case_swap", "Invert case of all alphabetic characters (Header-Name → hEADER-nAME)"),
    ("unicode_mapping", "Map characters to Unicode Mathematical Monospace equivalents (Header-Name → 𝙷𝚎𝚊𝚍𝚎𝚛-𝙽𝚊𝚖𝚎)"),
    ("add_x_prefix", "Add X- prefix to header name (Header-Name → X-Header_Name)")    
]

# Mutation characters: (character, description)
# Use the same format as the hardcoded values in the main script
test_mutations = [
    ("\x20", "space"),
    ("\x5f", "underscore"),
    ("\x2d", "hyphen"),
    ("\x09", "tab"),
    ("\x2c", "comma"),
    ("\x3b", "semicolon"),
    ("\x7a", "z"),
    ("\x0d", "CR"),
    ("\x0a", "LF"),
    ("\x00", "null byte")
]
