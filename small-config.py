#!/usr/bin/env python3
"""
Sample configuration file for hpdd

This file demonstrates the format for test configurations, transformations and mutation characters.
Users can copy this format and modify it as needed.
"""

# Test configurations: (method, header, valid_value, invalid_value)
test_configurations = [
    ("POST", "Content-Length", "0", "z"),
    ("POST", "Transfer-Encoding", "chunked", "invalid@ value# test$"),
    ("POST", "Expect", "100-continue", "invalid@ value# test$")
]

# Transformation functions: (function_name, description)
test_transformations = [
    ("hyphen_to_underscore", "Replace hyphens with underscores (Header-Name → Header_Name)"),
    ("unicode_mapping", "Map characters to Unicode Mathematical Monospace equivalents (Header-Name → 𝙷𝚎𝚊𝚍𝚎𝚛-𝙽𝚊𝚖𝚎)")
]

# Mutation characters: (character, description)
# Use the same format as the hardcoded values in the main script
test_mutations = [
    ("\x20", "space"),
    ("\x5f", "underscore"),
    ("\x2d", "hyphen"),
    ("\x09", "tab"),
    ("\x00", "null byte")
]
