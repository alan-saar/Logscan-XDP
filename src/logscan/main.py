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
    parser = argparse.ArgumentParser(description="Logscan-XDP Daemon")
    parser.add_argument("--log", type=str, required=True, help="Caminho do log a ser monitorado (ex: /var/log/auth.log)")
    parser.add_argument("--container-name", type=str, help="Nome do container docker (para ambiente de teste Containerlab)", default=None)
    args = parser.parse_args()

    print(f"[*] Iniciando Logscan-XDP Daemon...")
    print(f"[*] Monitorando arquivo: {args.log}")
    if args.container_name:
        print(f"[*] Modo Teste Ativo: Atualizando BPF Map via docker exec no container '{args.container_name}'")

    tailer = LogTailer(args.log)
    scanner = LogScanner()
    bpf_updater = BpfUpdater(map_name="malicious_ips", container_name=args.container_name)

    try:
        # Pipeline contínuo
        for line in tailer.tail():
            if not line:
                time.sleep(0.1)
                continue
            
            # Submete a linha ao motor do Logscan
            anomaly_detected, source_ip = scanner.process_log_line(line)
            
            if anomaly_detected and source_ip:
                print(f"[!] Cluster anômalo detectado! IP de origem: {source_ip}")
                # Atualiza o mapa BPF no kernel
                bpf_updater.block_ip(source_ip)
                
    except KeyboardInterrupt:
        print("\n[*] Encerrando Logscan-XDP Daemon...")

if __name__ == "__main__":
    main()
