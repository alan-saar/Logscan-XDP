#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finalidade do Arquivo: Gerador de Tráfego e Replay de Logs.
Este script roda no contêiner 'traffic_generator' e faz o replay de logs HDFS
via rede UDP para o Nó Vítima, permitindo simular cenários de carga normal e "Log Storm"
(tempestades de logs) para validação científica da aceleração eBPF.

O script executa as seguintes etapas:
1. Lê o arquivo de amostragem concentrada 'HDFS_test.log'.
2. Conecta-se via socket UDP ao IP de destino (Nó Vítima na porta 9999).
3. Transmite as mensagens linha por linha.
4. Suporta dois modos de operação:
   - Modo Rate-Limited (ex: 100/500/1000 logs/seg) para validar rate limit e acurácia temporal.
   - Modo Flood (velocidade máxima) para estressar a CPU da IA e validar o alívio do eBPF.
5. Imprime relatório de telemetria de envio com tempo e taxa de transmissão real obtida.
"""

import os
import sys
import time
import socket
import argparse

def main():
    base_dir = "/home/saar/code/mestrado/logscan-xdp"
    default_log = os.path.join(base_dir, "full_dataset/HDFS/HDFS_test.log")

    parser = argparse.ArgumentParser(description="Logscan-XDP Traffic Generator / Replay Tool")
    parser.add_argument("--log", type=str, default=default_log, help="Caminho do arquivo de logs para replay")
    parser.add_argument("--ip", type=str, default="10.10.10.1", help="IP do Nó Vítima (servidor de logs)")
    parser.add_argument("--port", type=int, default=9999, help="Porta UDP do receptor")
    parser.add_argument("--rate", type=int, default=0, help="Taxa limite de logs por segundo (0 = Flood / ilimitado)")
    args = parser.parse_args()

    print("==================================================")
    print("🚀 LOGSCAN-XDP TRAFFIC GENERATOR / REPLAY DA REDE")
    print("==================================================")

    if not os.path.exists(args.log):
        print(f"[❌] Erro: Arquivo de log não encontrado em: {args.log}")
        print("    Certifique-se de rodar primeiro o script prepare_test_data.py!")
        sys.exit(1)

    # 1. Carrega todas as mensagens de log em memória para transmissão de baixíssima latência
    print(f"[*] Carregando {args.log} em memória...")
    with open(args.log, "r", encoding="utf-8") as f:
        log_lines = [line.encode("utf-8") for line in f if line.strip()]

    total_lines = len(log_lines)
    print(f"[✅] Total de {total_lines} linhas carregadas na memória.")

    # 2. Inicializa o socket UDP de rede
    print(f"[*] Configurando socket UDP para {args.ip}:{args.port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Configura buffer de envio estendido no socket para evitar gargalos em modo flood
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)

    # input("\n[Pressione ENTER para iniciar a transmissão do Replay...]\n")

    print("[*] Transmitindo mensagens de log...")
    start_time = time.time()
    sent_count = 0

    if args.rate > 0:
        # Modo Rate-Limited controlado
        delay = 1.0 / args.rate
        for line in log_lines:
            sock.sendto(line, (args.ip, args.port))
            sent_count += 1
            time.sleep(delay)
            
            if sent_count % 5000 == 0:
                elapsed = time.time() - start_time
                print(f"    - Enviados {sent_count}/{total_lines} logs (Tempo decorrido: {elapsed:.2f}s)...")
    else:
        # Modo Flood (Velocidade máxima de I/O de rede)
        for line in log_lines:
            sock.sendto(line, (args.ip, args.port))
            sent_count += 1
            
            if sent_count % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"    - Enviados {sent_count}/{total_lines} logs (Modo Flood | Tempo: {elapsed:.2f}s)...")

    duration = time.time() - start_time
    avg_rate = sent_count / duration if duration > 0 else sent_count

    print("\n==================================================")
    print("📊 TELEMETRIA DE TRANSMISSÃO CONCLUÍDA:")
    print("==================================================")
    print(f"-> Logs transmitidos com sucesso   : {sent_count}/{total_lines}")
    print(f"-> Tempo total de transmissão      : {duration:.3f} segundos")
    print(f"-> Taxa de envio média alcançada   : {avg_rate:.2f} logs/segundo")
    print(f"-> Endereço IP do Nó Vítima        : {args.ip}:{args.port}")
    print("==================================================")

    sock.close()

if __name__ == "__main__":
    main()
