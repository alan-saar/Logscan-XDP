import logging
from logscan.scanner import LogScanner

# Teste 1: Poucos logs (não atinge min_samples)
print("--- TESTE 1: Ruído (1 log) ---")
scanner = LogScanner(eps=0.5, min_samples=3)
logs_noise = [
    "Jan 12 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.10.2 port 22 ssh2"
]
print("IPs Anômalos:", scanner.process_window(logs_noise))

# Teste 2: Rajada (atinge min_samples=3)
print("\n--- TESTE 2: Rajada de 3 logs ---")
logs_burst = [
    "Jan 12 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.10.2 port 22 ssh2",
    "Jan 12 10:00:01 server sshd[1235]: Failed password for invalid user admin from 192.168.10.2 port 22 ssh2",
    "Jan 12 10:00:02 server sshd[1236]: Failed password for invalid user admin from 192.168.10.2 port 22 ssh2"
]
print("IPs Anômalos:", scanner.process_window(logs_burst))
