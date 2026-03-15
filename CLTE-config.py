#!/usr/bin/env python3
"""
Sample configuration file for hpdd

This file demonstrates the format for test configurations, transformations and mutation characters.
Users can copy this format and modify it as needed.
"""

# Test configurations: (method, header, valid_value, invalid_value)
test_configurations = [
    ("POST", "Content-Length", "0", "z"),
    ("POST", "Transfer-Encoding", "chunked", "invalid@ value# test$")
]

# Mutation characters: (character, description)
# Use the same format as the hardcoded values in the main script
test_mutations = [
    ("\x5f", "underscore"),
    ("\x09", "tab")
]
