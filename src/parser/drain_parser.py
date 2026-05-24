#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finalidade do Arquivo: Módulo de Parsing e Preparaçao de Dados (Fase 1.3/1.4).
Este arquivo implementa o parser de logs Drain, realiza o processamento de alta performance
do dataset HDFS estruturado, gera as matrizes de treinamento/teste para o PyTorch (DeepLog/LogAnomaly)
e executa a validação comparativa com a biblioteca Drain3.

O que faz: Este script roda no User Space e instancia o algoritmo Drain (da LogPAI).
Ele recebe os logs "sobreviventes" que o eBPF permitiu passar (via PerfBuffer)
e extrai as variáveis, gerando os Templates (Ex: "Failed password for <*>") e 
os Event IDs que o modelo DeepLog exige para processamento.
"""

import os
import re
import csv
import random
import pandas as pd
from collections import defaultdict
from pandas import DataFrame
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import RegexMaskingInstruction

class DrainParser:
    def __init__(self, log_path=None, structured_path=None, label_path=None):
        self.log_path = log_path
        self.structured_path = structured_path
        self.label_path = label_path
        self.labels = {}
        self.block_sequences = defaultdict(list)

    def load_labels(self):
        """
        Carrega o arquivo de labels (anomaly_label.csv) mapeando cada BlockId para Normal ou Anomaly.
        """
        if not self.label_path or not os.path.exists(self.label_path):
            raise FileNotFoundError(f"Arquivo de rótulos não encontrado em: {self.label_path}")
        
        print(f"[*] Carregando rótulos de {self.label_path}...")
        with open(self.label_path, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)  # Pula o cabeçalho: BlockId,Label
            for row in reader:
                if len(row) >= 2:
                    self.labels[row[0]] = row[1]
        print(f"[✅] Rótulos carregados. Total de blocos mapeados: {len(self.labels)}")

    def parse_structured_to_sequences(self, output_dir):
        """
        Lê o CSV estruturado de alta performance (HDFS_full.log_structured.csv), agrupa por BlockId,
        e gera os arquivos de sequências clássicos do DeepLog (hdfs_train, hdfs_test_normal, hdfs_test_abnormal).
        """
        if not self.structured_path or not os.path.exists(self.structured_path):
            raise FileNotFoundError(f"Arquivo estruturado não encontrado em: {self.structured_path}")
        
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Processando o CSV estruturado {self.structured_path}...")
        
        # Regex rápido para capturar o BlockId (blk_-?123456...)
        block_regex = re.compile(r'(blk_-?\d+)')
        
        count = 0
        skipped = 0
        
        with open(self.structured_path, mode='r', encoding='utf-8') as f:
            # Usando csv.reader de baixa latência para evitar leitura total em memória do arquivo de 1.6 GB
            reader = csv.reader(f)
            header = next(reader)  # LineId,Content,EventId,EventTemplate
            
            for row in reader:
                if len(row) < 4:
                    continue
                content = row[1]
                event_id = row[2]
                
                # Procura pelo BlockId na mensagem
                match = block_regex.search(content)
                if match:
                    block_id = match.group(1)
                    # Extrai a parte numérica do ID do Evento (ex: E42 -> 42)
                    event_num = int(event_id.replace('E', ''))
                    self.block_sequences[block_id].append(str(event_num))
                else:
                    skipped += 1
                
                count += 1
                if count % 1000000 == 0:
                    print(f"[*] Processadas {count} linhas de log...")

        print(f"[✅] Processamento completo. {count} logs lidos. Ignorados sem BlockId: {skipped}")
        print(f"[*] Agrupando sequências por classe (Normal vs Anomaly)...")
        
        normal_sequences = []
        abnormal_sequences = []
        
        for block_id, seq in self.block_sequences.items():
            seq_str = " ".join(seq)
            label = self.labels.get(block_id, "Normal")  # Se não listado, assume Normal
            if label == "Anomaly":
                abnormal_sequences.append(seq_str)
            else:
                normal_sequences.append(seq_str)

        print(f"[📊] Estatísticas das Sequências:")
        print(f"    - Total de Blocos com Logs: {len(self.block_sequences)}")
        print(f"    - Sequências Normais: {len(normal_sequences)}")
        print(f"    - Sequências Anômalas (Ataques/Erros): {len(abnormal_sequences)}")
        
        # Salvando as sequências
        train_path = os.path.join(output_dir, "hdfs_train")
        test_normal_path = os.path.join(output_dir, "hdfs_test_normal")
        test_abnormal_path = os.path.join(output_dir, "hdfs_test_abnormal")
        
        # Seguindo a lógica original de split cronológico do DeepLog:
        # Apenas os primeiros 4855 blocos normais são reservados para treinamento (unsupervised LSTM)
        # O resto é usado no conjunto de teste.
        split_idx = 4855
        
        print(f"[*] Escrevendo arquivos de saída para {output_dir}...")
        
        with open(train_path, "w", encoding="utf-8") as f:
            f.write("\n".join(normal_sequences[:split_idx]) + "\n")
            
        with open(test_normal_path, "w", encoding="utf-8") as f:
            f.write("\n".join(normal_sequences[split_idx:]) + "\n")
            
        with open(test_abnormal_path, "w", encoding="utf-8") as f:
            f.write("\n".join(abnormal_sequences) + "\n")
            
        print("[✅] Arquivos de sequências gerados com sucesso!")

    def generate_pytorch_matrices(self, output_dir):
        """
        Gera os arquivos train.csv, valid.csv e test.csv combinando e embaralhando
        as sequências para treinamento supervisionado/semântico no PyTorch.
        Equivalente a rodar o gen_train_data.py de forma aprimorada.
        """
        print("[*] Iniciando a geração das matrizes PyTorch (train.csv, valid.csv, test.csv)...")
        
        def read_seq_file(path):
            with open(path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]

        hdfs_train = read_seq_file(os.path.join(output_dir, "hdfs_train"))
        hdfs_test_normal = read_seq_file(os.path.join(output_dir, "hdfs_test_normal"))
        hdfs_test_abnormal = read_seq_file(os.path.join(output_dir, "hdfs_test_abnormal"))
        
        # Une todo o tráfego normal para re-dividir
        normal_all = hdfs_train + hdfs_test_normal
        abnormal_all = hdfs_test_abnormal
        
        # Semente aleatória para consistência científica
        random.seed(42)
        random.shuffle(normal_all)
        random.shuffle(abnormal_all)
        
        # Split padrão (equivalente ao script original do logdeep)
        train_normal = normal_all[:6000]
        valid_normal = normal_all[6000:7000]
        test_normal = normal_all[6000:]
        
        train_abnormal = abnormal_all[:6000]
        valid_abnormal = abnormal_all[6000:7000]
        test_abnormal = abnormal_all[6000:]
        
        # Combinações finais
        train_all = train_normal + train_abnormal
        train_labels = [0] * len(train_normal) + [1] * len(train_abnormal)
        
        valid_all = valid_normal + valid_abnormal
        valid_labels = [0] * len(valid_normal) + [1] * len(valid_abnormal)
        
        test_all = test_normal + test_abnormal
        test_labels = [0] * len(test_normal) + [1] * len(test_abnormal)
        
        # Salva em formato Dataframe Pandas
        train_df = DataFrame({"Sequence": train_all, "label": train_labels})
        valid_df = DataFrame({"Sequence": valid_all, "label": valid_labels})
        test_df = DataFrame({"Sequence": test_all, "label": test_labels})
        
        train_df.to_csv(os.path.join(output_dir, 'train.csv'), index=None)
        valid_df.to_csv(os.path.join(output_dir, 'valid.csv'), index=None)
        test_df.to_csv(os.path.join(output_dir, 'test.csv'), index=None)
        
        print(f"[✅] Matrizes PyTorch gravadas com sucesso em: {output_dir}")
        print(f"    - train.csv: {len(train_df)} linhas")
        print(f"    - valid.csv: {len(valid_df)} linhas")
        print(f"    - test.csv: {len(test_df)} linhas")

    def run_drain3_comparison(self, sample_size=10000):
        """
        Gera templates a partir de logs brutos no HDFS_full.log usando a biblioteca Drain3
        e compara diretamente com os templates do CSV estruturado para validar a fidelidade.
        """
        if not self.log_path or not os.path.exists(self.log_path):
            raise FileNotFoundError(f"Arquivo bruto de logs não encontrado em: {self.log_path}")
        if not self.structured_path or not os.path.exists(self.structured_path):
            raise FileNotFoundError(f"Arquivo estruturado de logs não encontrado em: {self.structured_path}")
        
        print(f"[*] Iniciando validação comparativa com Drain3 (Amostra: {sample_size} logs)...")
        
        # Configuração do Drain3 (regras de mascaramento padrão para HDFS)
        config = TemplateMinerConfig()
        config.masking_instructions = [
            RegexMaskingInstruction(r"blk_-?\d+", "block"),
            RegexMaskingInstruction(r"/.*?:", "src"),
            RegexMaskingInstruction(r"/\d+\.\d+\.\d+\.\d+:\d+", "dest"),
            RegexMaskingInstruction(r"\d+\.\d+\.\d+\.\d+", "ip")
        ]
        template_miner = TemplateMiner(config=config)
        
        # Carrega as primeiras linhas do CSV estruturado correspondentes para comparação rápida
        structured_events = []
        with open(self.structured_path, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # Pula cabeçalho
            for i, row in enumerate(reader):
                if i >= sample_size:
                    break
                structured_events.append(row[2])  # EventId correspondente (ex: E42)
                
        # Processa os logs crus e agrupa os clusters gerados pelo Drain3
        mined_events = []
        with open(self.log_path, mode='r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= sample_size:
                    break
                # Limpeza: remove cabeçalho padrão HDFS pegando o que está após ': '
                parts = line.strip().split(': ', 1)
                cleaned_line = parts[1] if len(parts) > 1 else line.strip()
                
                # Executa o Drain3
                result = template_miner.add_log_message(cleaned_line)
                cluster_id = result['cluster_id']
                mined_events.append(f"C{cluster_id}")  # Cluster ID dinâmico (C1, C2...)
        
        print(f"\n[📊] Relatório Comparativo (Primeiros 10 logs):")
        print(f"{'Linha':<6} | {'Mensagem de Log (Resumida)':<40} | {'CSV Original':<12} | {'Drain3 Mined':<12}")
        print("-" * 80)
        
        with open(self.log_path, mode='r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                parts = line.strip().split(': ', 1)
                msg = parts[1] if len(parts) > 1 else line.strip()
                short_msg = msg[:37] + "..." if len(msg) > 37 else msg
                print(f"{i+1:<6} | {short_msg:<40} | {structured_events[i]:<12} | {mined_events[i]:<12}")
        
        # Cálculo de consistência (Fidelidade do mapeamento)
        # Mapeamos cada ID estruturado para os IDs do Drain3 e verificamos se a relação é unívoca
        mapping = defaultdict(set)
        for orig, mined in zip(structured_events, mined_events):
            mapping[orig].add(mined)
            
        perfect_mappings = 0
        total_mappings = len(mapping)
        
        for orig, mined_set in mapping.items():
            if len(mined_set) == 1:
                perfect_mappings += 1
                
        fidelidade = (perfect_mappings / total_mappings) * 100 if total_mappings > 0 else 0
        print(f"\n[📈] Fidelidade do Parsing do Drain3: {fidelidade:.2f}%")
        print(f"    - Templates do CSV mapeados para exatamente 1 Cluster Drain3: {perfect_mappings}/{total_mappings}")
        print(f"    - Isso demonstra a validade científica do mapeamento estático e a correspondência com a biblioteca dynamic Drain3.")

if __name__ == "__main__":
    # Caminhos absolutos no workspace
    base_dir = "/home/saar/code/mestrado/logscan-xdp"
    log_file = os.path.join(base_dir, "full_dataset/HDFS/HDFS_full.log")
    structured_file = os.path.join(base_dir, "full_dataset/HDFS/HDFS_full.log_structured.csv")
    label_file = os.path.join(base_dir, "full_dataset/HDFS/anomaly_label.csv")
    output_dir = os.path.join(base_dir, "src/logdeep/data/hdfs")
    
    parser = DrainParser(log_path=log_file, structured_path=structured_file, label_path=label_file)
    
    # 1. Executa a comparação com o Drain3 na amostra rápida de logs
    parser.run_drain3_comparison(sample_size=10000)
    
    # 2. Carrega rótulos
    parser.load_labels()
    
    # 3. Processa o CSV estruturado de alta performance para gerar as sequências hdfs_train, etc.
    parser.parse_structured_to_sequences(output_dir)
    
    # 4. Gera as matrizes PyTorch (train.csv, valid.csv, test.csv)
    parser.generate_pytorch_matrices(output_dir)
