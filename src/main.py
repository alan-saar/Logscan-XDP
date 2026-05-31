#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Papel: O Orquestrador Inteligente (User-Space Daemon) 
O que faz:
1. Carrega e acopla nativamente o programa eBPF CO-RE ('src/ebpf/log_filter.bpf.o') usando bpftool autoattach.
2. Registra o PID do próprio receptor no mapa de processos monitorados ('pid_map').
3. Inicializa a IA do DeepLog LSTM em memória (configurada para CPU para máxima portabilidade).
4. Carrega o dicionário de hashes míopes ('hash_to_event.json') e o gabarito real ('HDFS_test_labels.json').
5. Inicia um socket UDP (porta 9999) para receber a transmissão de logs via rede.
6. Grava cada log recebido em disco, desencadeando o kprobe eBPF de alta velocidade no Kernel.
7. Ouve os logs sobreviventes (não-hotspots), realiza o parsing instantâneo de Event IDs via hashes estáticos,
   remonta as sessões por BlockId e executa a inferência online no DeepLog.
8. Monitora o consumo de recursos (CPU, RAM, tempos) em tempo real via psutil.
9. Consolida e exporta as métricas científicas finais para 'results/data/ebpf_accelerated.csv'.
"""

import os
import re
import csv
import sys
import json
import time
import socket
import struct
import shutil
import threading
import subprocess
import psutil
import torch
from collections import defaultdict, Counter

# Adiciona o diretório do logdeep ao path para importação correta
sys.path.append(os.path.join(os.path.dirname(__file__), "logdeep"))
from logdeep.models.lstm import deeplog

# Configurações globais
BASE_DIR = "/home/saar/code/mestrado/logscan-xdp"
MODEL_PATH = os.path.join(BASE_DIR, "src/logdeep/result/deeplog/deeplog_last.pth")
HASH_MAP_PATH = os.path.join(BASE_DIR, "full_dataset/HDFS/hash_to_event.json")
LABELS_PATH = os.path.join(BASE_DIR, "full_dataset/HDFS/HDFS_test_labels.json")
OUTPUT_CSV = os.path.join(BASE_DIR, "results/data/ebpf_accelerated.csv")
TEST_LOG_PATH = "/tmp/victim_received.log"

# Parâmetros da LSTM DeepLog
WINDOW_SIZE = 10
INPUT_SIZE = 1
HIDDEN_SIZE = 64
NUM_LAYERS = 2
NUM_CLASSES = 46
NUM_CANDIDATES = 9

# Estruturas compartilhadas entre as threads
session_sequences = defaultdict(list)
session_anomalies_detected = {}  # Mapeia BlockId -> bool (True se IA alertar anomalia)
active_blocks = set()

# Lock para garantir acesso thread-safe às sequências das sessões
data_lock = threading.Lock()

def calculate_fnv1a_miope_py(buf):
    """
    Função de Hashing FNV-1a Míope idêntica ao C do eBPF.
    """
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

def load_deeplog_model():
    """
    Carrega a rede neural LSTM pré-treinada do DeepLog em CPU.
    """
    print(f"[*] Carregando modelo DeepLog LSTM de {MODEL_PATH}...")
    try:
        model = deeplog(input_size=INPUT_SIZE, hidden_size=HIDDEN_SIZE, num_layers=NUM_LAYERS, num_keys=NUM_CLASSES)
        checkpoint = torch.load(MODEL_PATH, map_location="cpu")
        model.load_state_dict(checkpoint['state_dict'])
        model.to("cpu")
        model.eval()
        print("[✅] Modelo DeepLog carregado com sucesso em CPU.")
        return model
    except Exception as e:
        print(f"[❌] Falha ao carregar modelo PyTorch: {e}")
        sys.exit(1)

def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"[❌] Falha ao executar: {cmd}")
        print(f"    Stderr: {res.stderr.strip()}")
        sys.exit(1)
    return res

def load_ebpf_program():
    """
    Carrega o programa eBPF CO-RE nativamente via bpftool autoattach.
    """
    print("[*] Carregando e acoplando filtro eBPF no Kernel...")
    ebpf_obj = os.path.join(BASE_DIR, "src/ebpf/log_filter.bpf.o")
    bpf_prog_path = "/sys/fs/bpf/log_filter"
    bpf_maps_dir = "/sys/fs/bpf/log_filter_maps"

    # Limpa fixações anteriores
    run_cmd(f"rm -f {bpf_prog_path} && rm -rf {bpf_maps_dir}", check=False)

    try:
        run_cmd(f"bpftool prog load {ebpf_obj} {bpf_prog_path} pinmaps {bpf_maps_dir} autoattach")
        print("[✅] Filtro eBPF CO-RE carregado e Kprobe sys_write ativa no Kernel.")
    except Exception as e:
        print(f"[⚠️] Falha ao carregar eBPF no Kernel (ambiente sem privilégios?). Pulando controle de Kernel: {e}")
        return False
    return True

def register_receptor_pid(has_ebpf):
    """
    Registra o PID do receptor no pid_map do eBPF.
    """
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

def run_udp_receiver():
    """
    Thread Receptora: Escuta conexões UDP e grava logs em disco (gerando sys_write interceptadas).
    """
    print("[*] Inicializando socket receptor UDP na porta 9999...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 9999))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)

    # Abre o arquivo de log para escritas reais de syscall
    fd = os.open(TEST_LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)

    print("[✅] Receptor UDP pronto para receber logs.")
    
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            if not data:
                break
            # os.write direto garante a chamada imediata da syscall sys_write
            os.write(fd, data)
    except Exception as e:
        print(f"[⚠️] Conexão do receptor finalizada: {e}")
    finally:
        os.close(fd)
        sock.close()

def evaluate_sequence(model, sequence):
    """
    Executa a inferência online no modelo DeepLog LSTM para a janela informada.
    Retorna True se for considerada uma anomalia (próximo evento fora dos top 9 candidatos).
    """
    if len(sequence) < WINDOW_SIZE + 1:
        return False

    # Pega a janela deslizante e o label real de destino
    seq0 = sequence[-WINDOW_SIZE-1:-1]
    label = sequence[-1]

    # Mapeamento numérico de classes (ajustado de base 0 para a rede)
    seq0 = [x - 1 for x in seq0]
    label = label - 1

    # Vetor quantitativo padrão (frequências de ocorrências na janela)
    seq1 = [0] * NUM_CLASSES
    log_counter = Counter(seq0)
    for key in log_counter:
        if 0 <= key < NUM_CLASSES:
            seq1[key] = log_counter[key]

    with torch.no_grad():
        # Transforma em tensores PyTorch
        t_seq0 = torch.tensor(seq0, dtype=torch.float).view(-1, WINDOW_SIZE, INPUT_SIZE)
        t_seq1 = torch.tensor(seq1, dtype=torch.float).view(-1, NUM_CLASSES, INPUT_SIZE)
        t_label = torch.tensor(label).view(-1)

        output = model(features=[t_seq0, t_seq1], device="cpu")
        predicted = torch.argsort(output, 1)[0][-NUM_CANDIDATES:]

        if t_label not in predicted:
            return True  # Anomalia detectada
    return False

def main():
    print("==================================================")
    print("🚀 INICIANDO LOGSCAN-XDP ORQUESTRADOR DE ACELERAÇÃO")
    print("==================================================")

    # 1. Setup inicial e carregamento de gabaritos e modelos
    model = load_deeplog_model()

    if not os.path.exists(HASH_MAP_PATH) or not os.path.exists(LABELS_PATH):
        print("[❌] Erro: Arquivos de mapeamento de hash ou rótulos não encontrados.")
        print("    Certifique-se de rodar primeiro o prepare_test_data.py!")
        sys.exit(1)

    print("[*] Carregando mapa de hashes...")
    with open(HASH_MAP_PATH, "r") as f:
        # Carrega e converte as chaves do JSON de string para inteiros
        hash_to_event = {int(k): v for k, v in json.load(f).items()}

    print("[*] Carregando rótulos reais de teste...")
    with open(LABELS_PATH, "r") as f:
        test_labels = json.load(f)

    print(f"[✅] Gabaritos carregados. Hashes mapeados: {len(hash_to_event)} | Blocos de teste: {len(test_labels)}")

    # 2. Carrega o eBPF no Kernel
    has_ebpf = load_ebpf_program()

    # 3. Inicializa o Receptor UDP em thread paralela
    rec_thread = threading.Thread(target=run_udp_receiver, daemon=True)
    rec_thread.start()

    # Registra o PID do receptor no eBPF
    register_receptor_pid(has_ebpf)

    print("\n[*] Aguardando início do tráfego para processamento da IA...")
    
    # 4. Loop de Escuta e Inferência
    # Para máxima compatibilidade e robustez (mesmo se o bpftool event_pipe variar de versão),
    # nós faremos um tail -f inteligente no arquivo /tmp/victim_received.log.
    # Como o kprobe eBPF intercepta o sys_write, os logs sobreviventes que passarem
    # pela barreira do Kernel são gravados em disco de forma real, permitindo
    # a leitura contínua e processamento imediato!
    
    # Aguarda a criação do arquivo de log
    while not os.path.exists(TEST_LOG_PATH):
        time.sleep(0.5)

    # Abre o arquivo para leitura contínua (tail -f)
    f_log = open(TEST_LOG_PATH, "r", encoding="utf-8")
    block_regex = re.compile(r'(blk_-?\d+)')

    processed_logs = 0
    predictions_made = 0
    start_time = time.time()

    # Variáveis de monitoramento psutil
    max_cpu = 0.0
    max_mem = 0.0
    ps_proc = psutil.Process(os.getpid())

    try:
        while True:
            # Monitora telemetria de hardware
            cpu = ps_proc.cpu_percent(interval=None)
            mem = ps_proc.memory_percent()
            max_cpu = max(max_cpu, cpu)
            max_mem = max(max_mem, mem)

            line = f_log.readline()
            if not line:
                # Verifica se a transmissão de rede terminou (inatividade de 5 segundos)
                if processed_logs > 0 and (time.time() - last_log_time) > 5.0:
                    print("\n[*] Silêncio na rede de 5s detectado. Finalizando processamento...")
                    break
                time.sleep(0.01)
                continue

            last_log_time = time.time()
            processed_logs += 1

            # Extrai o BlockId para agrupar as sessões
            match = block_regex.search(line)
            if not match:
                continue

            block_id = match.group(1)
            active_blocks.add(block_id)

            # Calcula o Hash FNV-1a Míope do log recebido
            hash_id = calculate_fnv1a_miope_py(line)
            event_num = hash_to_event.get(hash_id)

            if event_num is None:
                # Se não mapeado, define como classe desconhecida ou ignora
                continue

            with data_lock:
                # Adiciona o ID do evento à sequência deslizante do bloco
                session_sequences[block_id].append(event_num)
                sequence = session_sequences[block_id]

            # Executa a inferência quando temos dados suficientes para a janela
            if len(sequence) >= WINDOW_SIZE + 1:
                predictions_made += 1
                # Se a IA já alertou anomalia anteriormente para este bloco, não precisa reavaliar (otimização)
                if not session_anomalies_detected.get(block_id, False):
                    is_abnormal = evaluate_sequence(model, sequence)
                    if is_abnormal:
                        session_anomalies_detected[block_id] = True

            if processed_logs % 5000 == 0:
                print(f"    - Processados {processed_logs} logs sobreviventes (IA predictions: {predictions_made})...")

    except KeyboardInterrupt:
        print("[*] Interrompido pelo usuário.")
    finally:
        f_log.close()

    duration = time.time() - start_time - 5.0  # Desconta o tempo de inatividade de 5s do timeout
    print(f"\n[✅] Processamento de logs concluído em {duration:.2f} segundos.")

    # 5. Cálculo Científico das Métricas de Acurácia (Precision, Recall, F1)
    print("[*] Calculando métricas de acurácia de IA...")
    TP = 0  # Verdadeiro Positivo
    FP = 0  # Falso Positivo
    FN = 0  # Falso Negativo
    TN = 0  # Verdadeiro Negativo

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

    print("\n==================================================")
    print("📊 RESULTADOS E TELEMETRIA DO ORQUESTRADOR ACELERADO:")
    print("==================================================")
    print(f"-> Total de logs processados por IA: {processed_logs}")
    print(f"-> Total de blocos únicos avaliados: {len(active_blocks)}")
    print(f"-> Verdadeiros Positivos (TP)      : {TP}")
    print(f"-> Falsos Positivos (FP)           : {FP}")
    print(f"-> Falsos Negativos (FN)           : {FN}")
    print(f"-> Verdadeiros Negativos (TN)      : {TN}")
    print(f"--------------------------------------------------")
    print(f"-> Precision (Precisão da IA)      : {precision:.3f}%")
    print(f"-> Recall (Sensibilidade da IA)    : {recall:.3f}%")
    print(f"-> F1-Score da Detecção            : {f1_score:.3f}%")
    print(f"-> Tempo total de processamento    : {duration:.2f} segundos")
    print(f"-> Pico de uso de CPU              : {max_cpu:.2f}%")
    print(f"-> Pico de uso de RAM              : {max_mem:.2f}%")
    print("==================================================")

    # 6. Grava os resultados oficiais no CSV
    print(f"[*] Exportando resultados consolidados para {OUTPUT_CSV}...")
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    with open(OUTPUT_CSV, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Precision", "Recall", "F1_Score",
            "TotalProcessedLogs", "EvaluationTimeSeconds",
            "Max_CPU_Percent", "Max_Memory_Percent"
        ])
        writer.writerow([
            precision, recall, f1_score,
            processed_logs, duration,
            max_cpu, max_mem
        ])

    # 7. Cleanup final do eBPF
    if has_ebpf:
        print("[*] Descarregando filtro eBPF e limpando mapas...")
        run_cmd("rm -f /sys/fs/bpf/log_filter && rm -rf /sys/fs/bpf/log_filter_maps", check=False)
    
    # Limpa arquivo temporário
    if os.path.exists(TEST_LOG_PATH):
        os.remove(TEST_LOG_PATH)

    print("[✅] Orquestrador Logscan finalizado com sucesso.")

if __name__ == "__main__":
    main()
