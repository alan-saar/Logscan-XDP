#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finalidade do Arquivo: Orquestrador da Coleta de Baseline (Fase 2.3).
Este script inicia o treinamento e a inferência do DeepLog, monitora o consumo
de recursos do sistema (CPU e RAM) em tempo real usando a biblioteca psutil
e grava os resultados científicos finais em 'results/data/baseline.csv'.

"""

import os
import re
import csv
import time
import psutil
import subprocess

def monitor_process(proc, interval=0.5):
    """
    Monitora o uso de CPU e Memória de um processo em execução.
    Retorna os valores máximos registrados.
    """
    max_cpu = 0.0
    max_mem = 0.0
    
    try:
        ps_proc = psutil.Process(proc.pid)
        while proc.poll() is None:
            # Obtém estatísticas do processo e filhos recursivamente
            try:
                cpu = ps_proc.cpu_percent(interval=None)
                # O ps_proc.cpu_percent() no primeiro chamado pode retornar 0, 
                # então dividimos pela quantidade de cores para ter o percentual real se necessário,
                # mas o psutil já gerencia isso bem.
                mem = ps_proc.memory_percent()
                
                # Soma filhos se houver
                for child in ps_proc.children(recursive=True):
                    try:
                        cpu += child.cpu_percent(interval=None)
                        mem += child.memory_percent()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                max_cpu = max(max_cpu, cpu)
                max_mem = max(max_mem, mem)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            time.sleep(interval)
    except Exception as e:
        print(f"[⚠️] Falha ao monitorar processo {proc.pid}: {e}")
        
    return max_cpu, max_mem

def main():
    base_dir = "/home/saar/code/mestrado/logscan-xdp"
    demo_dir = os.path.join(base_dir, "src/logdeep/demo")
    results_dir = os.path.join(base_dir, "results/data")
    os.makedirs(results_dir, exist_ok=True)
    
    python_bin = os.path.join(base_dir, ".venv/bin/python")
    
    print("==================================================")
    print("🚀 INICIANDO PIPELINE DE COLETA DA BASELINE (DEEPLOG)")
    print("==================================================")
    
    # --------------------------------------------------
    # Passo 1: Treinamento do DeepLog (15 épocas na GPU CUDA)
    # --------------------------------------------------
    print("[*] Iniciando treinamento do DeepLog...")
    train_start = time.time()
    
    train_proc = subprocess.Popen(
        [python_bin, "deeplog.py", "train"],
        cwd=demo_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Monitora recursos do treinamento
    train_max_cpu, train_max_mem = monitor_process(train_proc, interval=1.0)
    train_stdout, train_stderr = train_proc.communicate()
    train_duration = time.time() - train_start
    
    if train_proc.returncode != 0:
        print("[❌] Falha no treinamento do DeepLog!")
        print("Stdout:", train_stdout)
        print("Stderr:", train_stderr)
        return
        
    print(f"[✅] Treinamento finalizado em {train_duration:.2f} segundos.")
    print(f"    - Pico CPU: {train_max_cpu:.2f}% | Pico RAM: {train_max_mem:.2f}%")
    
    # --------------------------------------------------
    # Passo 2: Inferência / Predição (User Space)
    # --------------------------------------------------
    print("[*] Iniciando predição / inferência de teste...")
    predict_start = time.time()
    
    predict_proc = subprocess.Popen(
        [python_bin, "deeplog.py", "predict"],
        cwd=demo_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Monitora recursos da predição
    predict_max_cpu, predict_max_mem = monitor_process(predict_proc, interval=1.0)
    predict_stdout, predict_stderr = predict_proc.communicate()
    predict_duration = time.time() - predict_start
    
    if predict_proc.returncode != 0:
        print("[❌] Falha na inferência / predição do DeepLog!")
        print("Stdout:", predict_stdout)
        print("Stderr:", predict_stderr)
        return
        
    print(f"[✅] Inferência finalizada em {predict_duration:.2f} segundos.")
    print(f"    - Pico CPU: {predict_max_cpu:.2f}% | Pico RAM: {predict_max_mem:.2f}%")
    
    # --------------------------------------------------
    # Passo 3: Parse dos Resultados & Escrita do CSV
    # --------------------------------------------------
    print("[*] Processando dados para gerar o baseline.csv...")
    
    # Procura pela linha de métricas usando regex no stdout da predição
    # Exemplo: Precision: 95.830%, Recall: 93.300%, F1-measure: 94.540%
    precision_match = re.search(r'Precision:\s*([\d\.]+)%', predict_stdout)
    recall_match = re.search(r'Recall:\s*([\d\.]+)%', predict_stdout)
    f1_match = re.search(r'F1-measure:\s*([\d\.]+)%', predict_stdout)
    
    precision = float(precision_match.group(1)) if precision_match else 0.0
    recall = float(recall_match.group(1)) if recall_match else 0.0
    f1_score = float(f1_match.group(1)) if f1_match else 0.0
    
    # Encontra picos absolutos entre treino e inferência
    peak_cpu = max(train_max_cpu, predict_max_cpu)
    peak_mem = max(train_max_mem, predict_max_mem)
    
    csv_path = os.path.join(results_dir, "baseline.csv")
    
    with open(csv_path, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Precision", "Recall", "F1_Score", 
            "TrainingTimeSeconds", "PredictionTimeSeconds", 
            "Max_CPU_Percent", "Max_Memory_Percent"
        ])
        writer.writerow([
            precision, recall, f1_score,
            train_duration, predict_duration,
            peak_cpu, peak_mem
        ])
        
    print("==================================================")
    print(f"[✅] BASELINE COLETADA E GRAVADA EM: {csv_path}")
    print(f"    - Precision : {precision:.3f}%")
    print(f"    - Recall    : {recall:.3f}%")
    print(f"    - F1-Score  : {f1_score:.3f}%")
    print(f"    - Tempo Tr. : {train_duration:.2f}s | Tempo Pred. : {predict_duration:.2f}s")
    print(f"    - Pico CPU  : {peak_cpu:.2f}% | Pico RAM  : {peak_mem:.2f}%")
    print("==================================================")

if __name__ == "__main__":
    main()
