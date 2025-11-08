#!/usr/bin/env python3

import re

# Multiline string containing the throughput lines
data = """
"""

# Extract all numbers using regex
numbers = list(map(int, re.findall(r'Insert throughput: (\d+)', data)))

# Calculate average
average = sum(numbers) / len(numbers)

print(f"Average insert throughput: {average:.2f} pkt/s")

