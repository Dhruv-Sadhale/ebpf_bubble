#!/usr/bin/env python3

import re

# Multiline string containing the throughput lines
data = """
Insert throughput: 54083 pkt/s
Insert throughput: 156792 pkt/s
Insert throughput: 162736 pkt/s
Insert throughput: 183416 pkt/s
Insert throughput: 206280 pkt/s
Insert throughput: 190912 pkt/s
Insert throughput: 180312 pkt/s
Insert throughput: 179120 pkt/s
Insert throughput: 201896 pkt/s
Insert throughput: 188920 pkt/s
Insert throughput: 185792 pkt/s
Insert throughput: 204176 pkt/s
Insert throughput: 201024 pkt/s
Insert throughput: 188109 pkt/s
Insert throughput: 189539 pkt/s
Insert throughput: 211440 pkt/s
Insert throughput: 222960 pkt/s
Insert throughput: 193088 pkt/s
Insert throughput: 197544 pkt/s
Insert throughput: 225104 pkt/s
Insert throughput: 190904 pkt/s
Insert throughput: 189056 pkt/s
Insert throughput: 212088 pkt/s
Insert throughput: 200888 pkt/s
Insert throughput: 213984 pkt/s
Insert throughput: 190458 pkt/s
Insert throughput: 192222 pkt/s
Insert throughput: 190610 pkt/s
Insert throughput: 200007 pkt/s
Insert throughput: 389955 pkt/s
Insert throughput: 391042 pkt/s
Insert throughput: 391089 pkt/s
Insert throughput: 388200 pkt/s
Insert throughput: 389960 pkt/s
Insert throughput: 389969 pkt/s
Insert throughput: 388709 pkt/s
Insert throughput: 388288 pkt/s
Insert throughput: 388351 pkt/s
Insert throughput: 391600 pkt/s
Insert throughput: 392684 pkt/s
Insert throughput: 206693 pkt/s
"""

# Extract all numbers using regex
numbers = list(map(int, re.findall(r'Insert throughput: (\d+)', data)))

# Calculate average
average = sum(numbers) / len(numbers)

print(f"Average insert throughput: {average:.2f} pkt/s")

