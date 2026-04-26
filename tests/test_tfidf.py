from logscan.scanner import LogScanner

scanner = LogScanner()
logs = [
    "Jan 12 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.10.2 port 22 ssh2",
    "Jan 12 10:00:02 server sshd[1235]: Failed password for invalid user root from 192.168.10.2 port 22 ssh2",
    "Jan 12 10:00:05 server su[1236]: Successful su for root by user1"
]
print("--- PREPROCESSED LOGS ---")
for log in logs:
    print(scanner._preprocess_log(log))

print("\n--- PROCESSING WINDOW ---")
scanner.process_window(logs)
