#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
tests/labvm/sender_vm.py
Transmissor de logs (Replay de Dataset) para rodar na VM Atacante (192.168.122.101).
Envia mensagens via rede UDP para a VM Vítima (192.168.122.100).
"""

import os
import sys
import time
import socket
import argparse

def main():
    parser = argparse.ArgumentParser(description="Logscan-XDP VM Traffic Generator")
    parser.add_argument("--log", type=str, default="HDFS_test.log", help="Caminho do arquivo HDFS_test.log")
    parser.add_argument("--ip", type=str, default="192.168.122.100", help="IP da VM Vítima")
    parser.add_argument("--port", type=int, default=9999, help="Porta UDP do receptor")
    parser.add_argument("--rate", type=int, default=0, help="Taxa limite de logs por segundo (0 = Flood / velocidade máxima)")
    args = parser.parse_args()

    print("==================================================")
    print("🚀 VM TRAFFIC SENDER: LOGSCAN-XDP EXPERIMENTS")
    print(f"   Destino: {args.ip}:{args.port}")
    print(f"   Modo: " + ("UDP Flood" if args.rate == 0 else f"Controlado ({args.rate} logs/s)"))
    print("==================================================")

    if not os.path.exists(args.log):
        print(f"[❌] Erro: Arquivo de logs não encontrado em: {args.log}")
        print("    Certifique-se de copiar o HDFS_test.log para o mesmo diretório.")
        sys.exit(1)

    print(f"[*] Carregando {args.log} em memória...")
    with open(args.log, "r", encoding="utf-8") as f:
        log_lines = [line.encode("utf-8") for line in f if line.strip()]

    total_lines = len(log_lines)
    print(f"[✅] {total_lines} linhas carregadas na RAM.")

    # Inicializa o socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)  # Buffer de envio de 4MB

    print("[*] Iniciando a transmissão...")
    start_time = time.time()
    sent_count = 0

    if args.rate > 0:
        delay = 1.0 / args.rate
        for line in log_lines:
            sock.sendto(line, (args.ip, args.port))
            sent_count += 1
            time.sleep(delay)
            if sent_count % 5000 == 0:
                elapsed = time.time() - start_time
                print(f"    - Enviados {sent_count}/{total_lines} logs (Tempo: {elapsed:.2f}s)...")
    else:
        # Modo Flood (velocidade máxima)
        for line in log_lines:
            sock.sendto(line, (args.ip, args.port))
            sent_count += 1
            if sent_count % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"    - Enviados {sent_count}/{total_lines} logs (Flood | Tempo: {elapsed:.2f}s)...")

    duration = time.time() - start_time
    avg_rate = sent_count / duration if duration > 0 else sent_count

    print("\n==================================================")
    print("📊 TELEMETRIA DO ENVIO:")
    print("==================================================")
    print(f"-> Logs transmitidos com sucesso   : {sent_count}/{total_lines}")
    print(f"-> Tempo total de transmissão      : {duration:.3f} segundos")
    print(f"-> Taxa de envio média alcançada   : {avg_rate:.2f} logs/segundo")
    print("==================================================")

    sock.close()

if __name__ == "__main__":
    main()
