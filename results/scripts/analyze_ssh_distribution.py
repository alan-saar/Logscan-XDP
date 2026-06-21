import collections
import re

log_path = "/home/saar/code/mestrado/logscan-xdp/full_dataset/OpenSSH/OpenSSH_full.log"

# Parse month day hour minute second
# e.g. "Dec 10 06:55:46"
log_pattern = re.compile(r'^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})')

seconds_counts = collections.defaultdict(int)

print("Starting SSH log file read...")
total_lines = 0
matched_lines = 0
with open(log_path, 'r', errors='ignore') as f:
    for line in f:
        total_lines += 1
        m = log_pattern.match(line)
        if m:
            matched_lines += 1
            month, day, time_str = m.groups()
            second_key = f"{month} {day} {time_str}"
            seconds_counts[second_key] += 1

print(f"Finished reading {total_lines} lines. Matched timestamps: {matched_lines}")
print(f"Total unique seconds: {len(seconds_counts)}")

counts = list(seconds_counts.values())
if not counts:
    print("No valid timestamps found.")
    exit(0)

counts.sort()

import numpy as np
counts_arr = np.array(counts)

print("--- SSH Log Rate Statistics (Logs per Second) ---")
print(f"Min: {counts_arr.min()}")
print(f"Max: {counts_arr.max()}")
print(f"Mean: {counts_arr.mean():.2f}")
print(f"Median: {np.median(counts_arr)}")
print(f"75th percentile: {np.percentile(counts_arr, 75)}")
print(f"90th percentile: {np.percentile(counts_arr, 90)}")
print(f"95th percentile: {np.percentile(counts_arr, 95)}")
print(f"99th percentile: {np.percentile(counts_arr, 99)}")
print(f"99.9th percentile: {np.percentile(counts_arr, 99.9)}")

# Let's count how many seconds have > 2, > 5, > 10, > 20 logs/sec
for thresh in [2, 5, 10, 20, 50]:
    count_above = np.sum(counts_arr > thresh)
    pct = (count_above / len(counts_arr)) * 100
    print(f"Seconds with > {thresh} logs/sec: {count_above} ({pct:.4f}%)")

# Let's count how many IPs we can find
ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
ip_counts = collections.Counter()
with open(log_path, 'r', errors='ignore') as f:
    for line in f:
        ips = ip_pattern.findall(line)
        for ip in ips:
            ip_counts[ip] += 1

print(f"\nTotal unique IPs found: {len(ip_counts)}")
print("Top 10 most active IPs:")
for ip, count in ip_counts.most_common(10):
    print(f"  {ip}: {count} occurrences")
