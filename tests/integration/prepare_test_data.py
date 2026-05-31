#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finalidade do Arquivo: Preparador de Amostra de Logs de Teste (Fase 4.1).
Este script extrai uma fatia representativa de teste de 50.000 logs do dataset de 1.5 GB
para viabilizar a transmissão e replicação rápida de tráfego em rede virtual (UDP)
no Containerlab, mantendo a consistência científica com o conjunto de teste do DeepLog.

O script executa as seguintes etapas:
1. Carrega os rótulos de blocos do arquivo 'anomaly_label.csv'.
2. Seleciona 1000 blocos normais (pulando os 4855 primeiros usados para treino da IA).
3. Seleciona 1000 blocos anômalos para teste.
4. Varre linearmente o 'HDFS_full.log' de 1.5 GB em poucos segundos.
5. Filtra e extrai as linhas físicas de logs dos blocos selecionados para 'HDFS_test.log'.
6. Grava um gabarito científico 'HDFS_test_labels.json' com as labels reais apenas dos
   blocos extraídos para cálculo de acurácia em tempo real no orquestrador.
"""

import os
import re
import csv
import json
import sys
import struct

def calculate_fnv1a_miope_py(buf):
    if isinstance(buf, str):
        buf = buf.encode("utf-8")
    
    hash_val = 2166136261
    # Janela idêntica ao C: do byte 16 ao 48 (32 bytes de tamanho)
    window = buf[16:48]
    
    for b in window:
        if b == 0 or b == ord('\n') or b == ord('\r'):
            break
        if ord('0') <= b <= ord('9'):
            continue
        hash_val = hash_val ^ b
        hash_val = (hash_val * 16777619) & 0xffffffff
        
    return hash_val


def main():
    base_dir = "/home/saar/code/mestrado/logscan-xdp"
    log_file = os.path.join(base_dir, "full_dataset/HDFS/HDFS_full.log")
    label_file = os.path.join(base_dir, "full_dataset/HDFS/anomaly_label.csv")
    output_log = os.path.join(base_dir, "full_dataset/HDFS/HDFS_test.log")
    output_labels = os.path.join(base_dir, "full_dataset/HDFS/HDFS_test_labels.json")

    print("==================================================")
    print("🚀 PREPARANDO AMOSTRA DE DADOS DE TESTE HDFS")
    print("==================================================")

    if not os.path.exists(log_file) or not os.path.exists(label_file):
        print("[❌] Erro: Dataset HDFS bruto não encontrado na pasta full_dataset/HDFS/")
        sys.exit(1)

    # 1. Carrega o arquivo de labels de blocos
    print("[*] Carregando rótulos do anomaly_label.csv...")
    labels = {}
    normals = []
    anomalies = []

    with open(label_file, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # Pula cabeçalho BlockId,Label
        for row in reader:
            if len(row) >= 2:
                block_id, label = row[0], row[1]
                labels[block_id] = label
                if label == "Anomaly":
                    anomalies.append(block_id)
                else:
                    normals.append(block_id)

    print(f"[✅] Rótulos carregados. Normais: {len(normals)} | Anômalos: {len(anomalies)}")

    # 2. Seleciona os blocos de teste para a amostragem
    # Seguindo o split do DeepLog, pulamos os primeiros 4855 blocos normais (usados em hdfs_train)
    test_normals = normals[4855:4855 + 1000]
    test_anomalies = anomalies[:1000]

    selected_blocks_set = set(test_normals + test_anomalies)
    print(f"[*] Selecionados {len(selected_blocks_set)} blocos para a amostragem de teste.")

    # 3. Varre o HDFS_full.log e filtra as linhas dos blocos selecionados
    print("[*] Filtrando logs brutos de HDFS_full.log (Varredura rápida)...")
    block_regex = re.compile(r'(blk_-?\d+)')
    
    extracted_count = 0
    total_lines = 0
    actual_blocks_written = set()

    # Usando buffers grandes de leitura e escrita para máxima velocidade
    with open(log_file, "r", encoding="utf-8", buffering=10*1024*1024) as infile, \
         open(output_log, "w", encoding="utf-8", buffering=10*1024*1024) as outfile:
        
        for line in infile:
            total_lines += 1
            match = block_regex.search(line)
            if match:
                block_id = match.group(1)
                if block_id in selected_blocks_set:
                    outfile.write(line)
                    extracted_count += 1
                    actual_blocks_written.add(block_id)
            
            if total_lines % 2000000 == 0:
                print(f"    - Processados {total_lines} logs...")

    print(f"[✅] Extração finalizada. Total de linhas gravadas: {extracted_count}")

    # 4. Grava as labels reais dos blocos contidos na amostragem
    print("[*] Gerando gabarito de teste HDFS_test_labels.json...")
    test_labels_output = {}
    actual_normals = 0
    actual_anomalies = 0

    for block_id in actual_blocks_written:
        lbl = labels[block_id]
        test_labels_output[block_id] = lbl
        if lbl == "Anomaly":
            actual_anomalies += 1
        else:
            actual_normals += 1

    with open(output_labels, "w", encoding="utf-8") as f:
        json.dump(test_labels_output, f, indent=4)

    # 5. Gera e grava o mapeamento estático de Hash Míope -> Event ID
    print("[*] Gerando mapeamento de Hashing Míope para EventID (hash_to_event.json)...")
    hash_to_event = {}
    struct_file = os.path.join(base_dir, "full_dataset/HDFS/HDFS_full.log_structured.csv")
    
    with open(log_file, "r", encoding="utf-8") as f_raw, \
         open(struct_file, "r", encoding="utf-8") as f_struct:
         
         reader_struct = csv.reader(f_struct)
         next(reader_struct)  # Pula o cabeçalho
         
         count = 0
         for line_raw in f_raw:
             try:
                 row_struct = next(reader_struct)
             except StopIteration:
                 break
             
             if len(row_struct) < 4:
                 continue
                 
             event_id = row_struct[2]
             event_num = int(event_id.replace('E', ''))
             
             # Calcula o hash míope da linha bruta do log
             hash_id = calculate_fnv1a_miope_py(line_raw)
             hash_to_event[hash_id] = event_num
                 
    output_hash_map = os.path.join(base_dir, "full_dataset/HDFS/hash_to_event.json")
    with open(output_hash_map, "w", encoding="utf-8") as f:
        json.dump(hash_to_event, f, indent=4)
        
    print(f"[✅] Mapeamento gerado com {len(hash_to_event)} chaves exclusivas.")

    print("\n==================================================")
    print("📊 RELATÓRIO DO CONJUNTO DE TESTE GERADO:")
    print("==================================================")
    print(f"-> Arquivo de log gravado : {output_log}")
    print(f"-> Total de linhas de log : {extracted_count}")
    print(f"-> Total de blocos únicos : {len(actual_blocks_written)}")
    print(f"   - Blocos Normais       : {actual_normals}")
    print(f"   - Blocos Anômalos      : {actual_anomalies}")
    print(f"-> Gabarito JSON gravado  : {output_labels}")
    print(f"-> Mapeamento Hash JSON   : {output_hash_map}")
    print("==================================================")

if __name__ == "__main__":
    main()
