"""
@file main.py
@brief Ponto de entrada do Daemon Logscan.

Responsável por orquestrar a leitura de logs (log_tailer), o processamento 
algorítmico de agrupamento (scanner) e o envio dos IPs bloqueados 
ao Kernel via eBPF (bpf_updater).
"""

import argparse
import time
from log_tailer import LogTailer
from scanner import LogScanner
from bpf_updater import BpfUpdater

def main():
    """
    Função principal que inicia o pipeline infinito do Logscan.
    """
    parser = argparse.ArgumentParser(
        description="Logscan-XDP Daemon: Intelligent Log Analyzer and BPF Blocker",
        add_help=False
    )
    
    # Customizando o help para manter em inglês conforme pedido
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS,
                        help="Show this help message and exit")
    parser.add_argument("-l", "--log", type=str, required=True, 
                        help="Path to the log file to monitor (e.g., /var/log/auth.log)")
    parser.add_argument("-c", "--container-name", type=str, default=None,
                        help="Docker container name (for Containerlab testbed environment)")
    parser.add_argument("-w", "--window", type=int, default=10,
                        help="Time window in seconds for batch analysis (default: 10)")
    
    args = parser.parse_args()

    print(f"[*] Starting Logscan-XDP Daemon...")
    print(f"[*] Monitoring file: {args.log}")
    print(f"[*] Batch analysis window: {args.window} seconds")
    if args.container_name:
        print(f"[*] Test Mode Active: Updating BPF Map via docker exec in container '{args.container_name}'")

    tailer = LogTailer(args.log)
    scanner = LogScanner()
    bpf_updater = BpfUpdater(map_name="malicious_ips", container_name=args.container_name)

    current_batch = []
    window_start_time = time.time()

    try:
        # Pipeline contínuo (Micro-batching)
        for line in tailer.tail():
            if line:
                current_batch.append(line)
            
            # Checa se a janela temporal expirou
            current_time = time.time()
            if (current_time - window_start_time) >= args.window:
                if current_batch:
                    # Submete o lote inteiro ao motor do Logscan
                    anomalous_ips = scanner.process_window(current_batch)
                    
                    for source_ip in anomalous_ips:
                        print(f"[!] Cluster anômalo detectado! IP de origem: {source_ip}")
                        # Atualiza o mapa BPF no kernel
                        bpf_updater.block_ip(source_ip)
                
                # Reseta a janela
                current_batch = []
                window_start_time = time.time()
                
            # Evita busy-waiting agressivo caso não haja linhas novas
            if not line:
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        print("\n[*] Stopping Logscan-XDP Daemon...")

if __name__ == "__main__":
    main()
