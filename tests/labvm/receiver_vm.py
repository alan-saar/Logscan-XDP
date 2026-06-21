#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
tests/labvm/receiver_vm.py
Orquestrador de testes para rodar na VM Vítima (192.168.122.100).
Recebe logs via socket UDP, aplica o parser (Míope vs Drain3) e executa inferência LSTM.
Mede tempo, CPU, RAM, perda física aplicacional e drops de socket UDP relatados pelo Kernel Linux.
"""

import os
import re
import csv
import sys
import json
import time
import socket
import struct
import threading
import subprocess
import argparse
import psutil
import torch
from collections import defaultdict, Counter

# Adiciona o diretório do logdeep ao path para importação
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src"))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/logdeep"))
from logdeep.models.lstm import deeplog

# Configurações de caminhos baseadas na estrutura padrão do projeto
BASE_DIR = "/home/saar/code/mestrado/logscan-xdp"
MODEL_PATH = os.path.join(BASE_DIR, "src/logdeep/result/deeplog/deeplog_last.pth")
HASH_MAP_PATH = os.path.join(BASE_DIR, "full_dataset/HDFS/hash_to_event.json")
LABELS_PATH = os.path.join(BASE_DIR, "full_dataset/HDFS/HDFS_test_labels.json")
TEMPLATES_CSV_PATH = os.path.join(BASE_DIR, "full_dataset/HDFS/HDFS_full.log_templates.csv")
TEST_LOG_PATH = "/tmp/victim_received.log"

# Parâmetros DeepLog
WINDOW_SIZE = 10
INPUT_SIZE = 1
HIDDEN_SIZE = 64
NUM_LAYERS = 2
NUM_CLASSES = 46
NUM_CANDIDATES = 9

session_sequences = defaultdict(list)
session_anomalies_detected = {}
active_blocks = set()
data_lock = threading.Lock()

def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"[❌] Falha ao executar: {cmd}")
        print(f"    Stderr: {res.stderr.strip()}")
        sys.exit(1)
    return res

def load_ebpf_program():
    print("[*] Carregando e acoplando filtro eBPF no Kernel...")
    ebpf_obj = os.path.join(BASE_DIR, "src/ebpf/log_filter.bpf.o")
    bpf_prog_path = "/sys/fs/bpf/log_filter"
    bpf_maps_dir = "/sys/fs/bpf/log_filter_maps"

    run_cmd(f"rm -f {bpf_prog_path} && rm -rf {bpf_maps_dir}", check=False)

    try:
        run_cmd(f"bpftool prog load {ebpf_obj} {bpf_prog_path} pinmaps {bpf_maps_dir} autoattach")
        print("[✅] Filtro eBPF CO-RE carregado e Kprobe sys_write ativa no Kernel.")
    except Exception as e:
        print(f"[⚠️] Falha ao carregar eBPF no Kernel (ambiente sem privilégios?). Pulando controle de Kernel: {e}")
        return False
    return True

def register_receptor_pid(has_ebpf):
    if not has_ebpf:
        return
    my_pid = os.getpid()
    pid_bytes = struct.pack("<I", my_pid)
    key_hex = " ".join(f"0x{b:02x}" for b in pid_bytes)
    try:
        run_cmd(f"bpftool map update pinned /sys/fs/bpf/log_filter_maps/pid_map key {key_hex} value 0x01")
        print(f"[✅] Receptor PID {my_pid} registrado com sucesso no pid_map do Kernel.")
    except Exception as e:
        print(f"[⚠️] Falha ao atualizar pid_map: {e}")

def calculate_fnv1a_miope_py(buf):
    if isinstance(buf, str):
        buf = buf.encode("utf-8")
    hash_val = 2166136261
    window = buf[16:48]
    for b in window:
        if b == 0 or b == ord('\n') or b == ord('\r'):
            break
        if ord('0') <= b <= ord('9'):
            continue
        hash_val = hash_val ^ b
        hash_val = (hash_val * 16777619) & 0xffffffff
    return hash_val

def compile_templates_regex():
    templates = []
    if not os.path.exists(TEMPLATES_CSV_PATH):
        print(f"[❌] Erro: Arquivo de templates não encontrado em: {TEMPLATES_CSV_PATH}")
        return templates
    print(f"[*] Compilando templates do Drain3 de {TEMPLATES_CSV_PATH}...")
    with open(TEMPLATES_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) >= 2:
                event_id = int(row[0].replace('E', ''))
                template_str = row[1]
                parts = template_str.split('<*>')
                escaped_parts = [re.escape(p) for p in parts]
                regex_str = "^" + "(.*?)".join(escaped_parts) + "$"
                try:
                    compiled = re.compile(regex_str)
                    templates.append((event_id, compiled, template_str))
                except Exception as e:
                    print(f"[⚠️] Falha ao compilar regex para template {template_str}: {e}")
    print(f"[✅] Compilados {len(templates)} templates de regex.")
    return templates

def parse_log_with_drain3_templates(line, templates_regex):
    parts = line.strip().split(': ', 1)
    cleaned_line = parts[1] if len(parts) > 1 else line.strip()
    for event_id, regex_compiled, _ in templates_regex:
        if regex_compiled.match(cleaned_line):
            return event_id
    return None

def load_deeplog_model():
    print(f"[*] Carregando modelo DeepLog de {MODEL_PATH}...")
    try:
        model = deeplog(input_size=INPUT_SIZE, hidden_size=HIDDEN_SIZE, num_layers=NUM_LAYERS, num_keys=NUM_CLASSES)
        checkpoint = torch.load(MODEL_PATH, map_location="cpu")
        model.load_state_dict(checkpoint['state_dict'])
        model.to("cpu")
        model.eval()
        print("[✅] Modelo DeepLog LSTM carregado com sucesso.")
        return model
    except Exception as e:
        print(f"[❌] Falha ao carregar modelo: {e}")
        sys.exit(1)

def read_udp_kernel_stats():
    """
    Lê estatísticas de rede SNMP do kernel para quantificar descartes de pacotes UDP.
    """
    stats = {"InDatagrams": 0, "InErrors": 0, "RcvbufErrors": 0}
    try:
        if os.path.exists("/proc/net/snmp"):
            with open("/proc/net/snmp", "r") as f:
                lines = f.readlines()
            for i in range(len(lines)):
                if lines[i].startswith("Udp:"):
                    headers = lines[i].strip().split()[1:]
                    values = lines[i+1].strip().split()[1:]
                    val_dict = dict(zip(headers, [int(v) for v in values]))
                    stats["InDatagrams"] = val_dict.get("InDatagrams", 0)
                    stats["InErrors"] = val_dict.get("InErrors", 0)
                    stats["RcvbufErrors"] = val_dict.get("RcvbufErrors", 0)
                    break
    except Exception as e:
        print(f"[⚠️] Falha ao ler /proc/net/snmp: {e}")
    return stats

def run_udp_receiver(port):
    print(f"[*] Inicializando socket UDP na porta {port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    # Configura buffer de recepção de 4MB para atenuar descartes
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)

    fd = os.open(TEST_LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            if not data:
                break
            os.write(fd, data)
    except Exception as e:
        pass
    finally:
        os.close(fd)
        sock.close()

def run_local_file_writer(file_path):
    print(f"[*] Thread Local: Lendo e gravando {file_path} em {TEST_LOG_PATH}...")
    fd = os.open(TEST_LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                os.write(fd, line.encode("utf-8"))
    except Exception as e:
        print(f"[⚠️] Falha ao escrever arquivo localmente: {e}")
    finally:
        os.close(fd)
        print("[*] Thread Local: Escrita concluída.")

def evaluate_sequence(model, sequence):
    if len(sequence) < WINDOW_SIZE + 1:
        return False
    seq0 = sequence[-WINDOW_SIZE-1:-1]
    label = sequence[-1]
    seq0 = [x - 1 for x in seq0]
    label = label - 1
    seq1 = [0] * NUM_CLASSES
    log_counter = Counter(seq0)
    for key in log_counter:
        if 0 <= key < NUM_CLASSES:
            seq1[key] = log_counter[key]
    with torch.no_grad():
        t_seq0 = torch.tensor(seq0, dtype=torch.float).view(-1, WINDOW_SIZE, INPUT_SIZE)
        t_seq1 = torch.tensor(seq1, dtype=torch.float).view(-1, NUM_CLASSES, INPUT_SIZE)
        t_label = torch.tensor(label).view(-1)
        output = model(features=[t_seq0, t_seq1], device="cpu")
        predicted = torch.argsort(output, 1)[0][-NUM_CANDIDATES:]
        if t_label not in predicted:
            return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Logscan-XDP VM Receiver")
    parser.add_argument("--parser", type=str, choices=["miope", "drain3"], default="miope", help="Algoritmo de parsing")
    parser.add_argument("--output", type=str, default="results_vm.csv", help="Caminho do arquivo CSV de saída")
    parser.add_argument("--port", type=int, default=9999, help="Porta do receptor UDP")
    parser.add_argument("--scenario", type=str, default="UDP_Test", help="Identificador do cenário")
    parser.add_argument("--no-ebpf", action="store_true", help="Desativa o carregamento e execução do filtro eBPF no Kernel")
    parser.add_argument("--local-file", type=str, default=None, help="Caminho do arquivo de logs para simulação local, eliminando a rede")
    args = parser.parse_args()

    print("==================================================")
    print("🚀 VM LOG RECEIVER & EVALUATOR (LOGSCAN-XDP)")
    print(f"   Parser: {args.parser} | Cenário: {args.scenario} | eBPF: {'OFF' if args.no_ebpf else 'ON'}")
    print("==================================================")

    has_ebpf = False
    if not args.no_ebpf:
        has_ebpf = load_ebpf_program()
        if has_ebpf:
            register_receptor_pid(has_ebpf)

    model = load_deeplog_model()

    if not os.path.exists(LABELS_PATH):
        print(f"[❌] Erro: Arquivo de rótulos não encontrado em: {LABELS_PATH}")
        if has_ebpf:
            run_cmd("rm -f /sys/fs/bpf/log_filter && rm -rf /sys/fs/bpf/log_filter_maps", check=False)
        sys.exit(1)

    print("[*] Carregando rótulos reais de teste...")
    with open(LABELS_PATH, "r") as f:
        test_labels = json.load(f)

    templates_regex = []
    hash_to_event = {}
    if args.parser == "drain3":
        templates_regex = compile_templates_regex()
    else:
        print("[*] Carregando mapa de hashes para o parser Míope...")
        with open(HASH_MAP_PATH, "r") as f:
            hash_to_event = {int(k): v for k, v in json.load(f).items()}

    # Coleta de estatísticas SNMP iniciais do Kernel
    start_net_stats = read_udp_kernel_stats()

    # Inicializa receptor UDP ou Simulador de Escrita Local em thread paralela
    if args.local_file:
        rec_thread = threading.Thread(target=run_local_file_writer, args=(args.local_file,), daemon=True)
    else:
        rec_thread = threading.Thread(target=run_udp_receiver, args=(args.port,), daemon=True)
    rec_thread.start()

    if args.local_file:
        print(f"\n[*] Aguardando início da gravação do arquivo local {args.local_file}...")
    else:
        print("\n[*] Aguardando início do tráfego UDP...")

    while not os.path.exists(TEST_LOG_PATH):
        time.sleep(0.1)

    f_log = open(TEST_LOG_PATH, "r", encoding="utf-8")
    block_regex = re.compile(r'(blk_-?\d+)')

    processed_logs = 0
    predictions_made = 0
    start_time = time.time()
    last_log_time = time.time()

    max_cpu = 0.0
    max_mem = 0.0
    ps_proc = psutil.Process(os.getpid())

    try:
        while True:
            # Monitoramento de hardware
            cpu = ps_proc.cpu_percent(interval=None)
            mem = ps_proc.memory_percent()
            max_cpu = max(max_cpu, cpu)
            max_mem = max(max_mem, mem)

            line = f_log.readline()
            if not line:
                # Timeout de inatividade de 5 segundos
                if processed_logs > 0 and (time.time() - last_log_time) > 5.0:
                    print("\n[*] Timeout de rede de 5s atingido. Finalizando processamento da IA...")
                    break
                time.sleep(0.01)
                continue

            last_log_time = time.time()
            processed_logs += 1

            match = block_regex.search(line)
            if not match:
                continue

            block_id = match.group(1)
            active_blocks.add(block_id)

            if args.parser == "drain3":
                event_num = parse_log_with_drain3_templates(line, templates_regex)
            else:
                hash_id = calculate_fnv1a_miope_py(line)
                event_num = hash_to_event.get(hash_id)

            if event_num is None:
                continue

            with data_lock:
                session_sequences[block_id].append(event_num)
                sequence = session_sequences[block_id]

            if len(sequence) >= WINDOW_SIZE + 1:
                predictions_made += 1
                if not session_anomalies_detected.get(block_id, False):
                    is_abnormal = evaluate_sequence(model, sequence)
                    if is_abnormal:
                        session_anomalies_detected[block_id] = True

            if processed_logs % 5000 == 0:
                print(f"    - Processados {processed_logs} logs (Previsões feitas: {predictions_made})...")

    except KeyboardInterrupt:
        print("[*] Interrompido.")
    finally:
        f_log.close()
        if has_ebpf:
            print("[*] Descarregando filtro eBPF e limpando mapas...")
            run_cmd("rm -f /sys/fs/bpf/log_filter && rm -rf /sys/fs/bpf/log_filter_maps", check=False)

    duration = time.time() - start_time - 5.0
    print(f"\n[✅] IA finalizada em {duration:.2f} segundos.")

    # Estatísticas SNMP finais do Kernel
    end_net_stats = read_udp_kernel_stats()
    kernel_drops = end_net_stats["RcvbufErrors"] - start_net_stats["RcvbufErrors"]
    kernel_errors = end_net_stats["InErrors"] - start_net_stats["InErrors"]

    # Cálculo da Acurácia
    TP = 0
    FP = 0
    FN = 0
    TN = 0
    for block_id in active_blocks:
        real_label = test_labels.get(block_id)
        predicted_anomaly = session_anomalies_detected.get(block_id, False)
        if real_label == "Anomaly":
            if predicted_anomaly:
                TP += 1
            else:
                FN += 1
        else:
            if predicted_anomaly:
                FP += 1
            else:
                TN += 1

    precision = (100.0 * TP / (TP + FP)) if (TP + FP) > 0 else 0.0
    recall = (100.0 * TP / (TP + FN)) if (TP + FN) > 0 else 0.0
    f1_score = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Quantificação de perdas físicas
    total_logs_enviados = 42229
    perda_aplicacao_percent = ((total_logs_enviados - processed_logs) / total_logs_enviados) * 100.0

    print("\n==================================================")
    print("📊 RESULTADOS FINAIS DA EXPERIMENTAÇÃO EM VM:")
    print("==================================================")
    print(f"-> Logs Enviados pelo Atacante     : {total_logs_enviados}")
    print(f"-> Logs Recebidos pela Aplicação   : {processed_logs}")
    print(f"-> Perda Aplicacional de Logs (%) : {perda_aplicacao_percent:.3f}%")
    print(f"-> Drops de Buffer do Kernel (SNMP) : {kernel_drops} pacotes")
    print(f"-> Erros de Entrada UDP (Kernel)   : {kernel_errors} pacotes")
    print(f"--------------------------------------------------")
    print(f"-> Precision / Recall / F1-Score   : {precision:.2f}% / {recall:.2f}% / {f1_score:.2f}%")
    print(f"-> Tempo total de processamento    : {duration:.2f} segundos")
    print(f"-> Pico CPU / Pico RAM (%)         : {max_cpu:.2f}% / {max_mem:.2f}%")
    print("==================================================")

    # Gravação dos Resultados
    csv_exists = os.path.exists(args.output)
    with open(args.output, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not csv_exists:
            writer.writerow([
                "Scenario", "Parser", "LogsSent", "LogsReceived", "AppLossPercent",
                "KernelBufDrops", "KernelUdpErrors", "Precision", "Recall", "F1_Score",
                "DurationSeconds", "MaxCPU", "MaxRAM"
            ])
        writer.writerow([
            args.scenario, args.parser, total_logs_enviados, processed_logs, perda_aplicacao_percent,
            kernel_drops, kernel_errors, precision, recall, f1_score,
            duration, max_cpu, max_mem
        ])
    print(f"[✅] Resultados gravados em: {args.output}")

    if os.path.exists(TEST_LOG_PATH):
        os.remove(TEST_LOG_PATH)

if __name__ == "__main__":
    main()
