import collections
import datetime

log_path = "/home/saar/code/mestrado/logscan-xdp/full_dataset/HDFS/HDFS_full.log"

seconds_counts = collections.defaultdict(int)

print("Starting log file read...")
total_lines = 0
with open(log_path, 'r') as f:
    for line in f:
        total_lines += 1
        if total_lines % 2000000 == 0:
            print(f"Processed {total_lines} lines...")
        # Format is "YYMMDD HHMMSS" at the beginning of the line
        # e.g., "081109 203518"
        parts = line.strip().split()
        if len(parts) >= 2:
            date_str = parts[0]
            time_str = parts[1]
            if len(date_str) == 6 and len(time_str) == 6 and date_str.isdigit() and time_str.isdigit():
                second_key = date_str + " " + time_str
                seconds_counts[second_key] += 1

print(f"Finished reading {total_lines} lines.")
print(f"Total unique seconds: {len(seconds_counts)}")

counts = list(seconds_counts.values())
if not counts:
    print("No valid timestamps found.")
    exit(0)

counts.sort()

import numpy as np
counts_arr = np.array(counts)

print("--- Log Rate Statistics (Logs per Second) ---")
print(f"Min: {counts_arr.min()}")
print(f"Max: {counts_arr.max()}")
print(f"Mean: {counts_arr.mean():.2f}")
print(f"Median: {np.median(counts_arr)}")
print(f"75th percentile: {np.percentile(counts_arr, 75)}")
print(f"90th percentile: {np.percentile(counts_arr, 90)}")
print(f"95th percentile: {np.percentile(counts_arr, 95)}")
print(f"99th percentile: {np.percentile(counts_arr, 99)}")
print(f"99.9th percentile: {np.percentile(counts_arr, 99.9)}")

# Let's count how many seconds have > 10, > 50, > 100, > 500, > 1000 logs/sec
for thresh in [10, 50, 100, 500, 1000]:
    count_above = np.sum(counts_arr > thresh)
    pct = (count_above / len(counts_arr)) * 100
    print(f"Seconds with > {thresh} logs/sec: {count_above} ({pct:.4f}%)")
