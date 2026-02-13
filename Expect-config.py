#!/usr/bin/env python3
"""
Sample configuration file for header-discrepancy.py

This file demonstrates the format for test configurations, transformations and mutation characters.
Users can copy this format and modify it as needed.
"""

# Test configurations: (method, header, valid_value, invalid_value)
test_configurations = [
    ("POST", "Expect", "100-continue", "invalid@ value# test$")
]

# Transformation functions: (function_name, description)
test_transformations = [
    ("unicode_mapping", "Map characters to Unicode Mathematical Monospace equivalents (Header-Name → 𝙷𝚎𝚊𝚍𝚎𝚛-𝙽𝚊𝚖𝚎)")
]

# Mutation characters: (character, description)
# Use the same format as the hardcoded values in the main script
test_mutations = [
    ("\x20", "space"),
    ("\x5f", "underscore"),
    ("\x2d", "hyphen"),
    ("\x09", "tab")
]
