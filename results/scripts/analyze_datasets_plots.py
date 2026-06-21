#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
results/scripts/analyze_datasets_plots.py
Script para gerar gráficos comparativos entre os datasets HDFS e OpenSSH.
Salva os gráficos na pasta results/images/datasets/
"""

import os
import re
import collections
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuração de estilo para gráficos científicos e elegantes
sns.set_theme(style="whitegrid")
plt.rcParams.update({
    'font.size': 12,
    'axes.labelsize': 14,
    'axes.titlesize': 16,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'figure.titlesize': 18,
    'legend.fontsize': 12,
    'font.family': 'sans-serif'
})

# Caminhos dos datasets
HDFS_PATH = "/home/saar/code/mestrado/logscan-xdp/full_dataset/HDFS/HDFS_full.log"
SSH_PATH = "/home/saar/code/mestrado/logscan-xdp/full_dataset/OpenSSH/OpenSSH_full.log"
OUTPUT_DIR = "/home/saar/code/mestrado/logscan-xdp/results/images/datasets"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("[-] Processando dataset HDFS (isso pode levar alguns segundos)...")
hdfs_seconds = collections.defaultdict(int)
hdfs_timeline = []  # para manter a ordem temporal
total_hdfs_lines = 0

with open(HDFS_PATH, 'r') as f:
    for line in f:
        total_hdfs_lines += 1
        parts = line.strip().split()
        if len(parts) >= 2:
            date_str = parts[0]
            time_str = parts[1]
            if len(date_str) == 6 and len(time_str) == 6 and date_str.isdigit() and time_str.isdigit():
                sec_key = date_str + " " + time_str
                hdfs_seconds[sec_key] += 1
                if not hdfs_timeline or hdfs_timeline[-1] != sec_key:
                    hdfs_timeline.append(sec_key)

hdfs_rates = list(hdfs_seconds.values())
hdfs_time_series = [hdfs_seconds[k] for k in hdfs_timeline]

print(f"[+] HDFS: {total_hdfs_lines} logs, {len(hdfs_rates)} segundos únicos. Taxa máx: {max(hdfs_rates)} logs/s")

print("[-] Processando dataset OpenSSH...")
ssh_seconds = collections.defaultdict(int)
ssh_timeline = []
ssh_ips = collections.Counter()
total_ssh_lines = 0

ssh_time_pattern = re.compile(r'^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})')
ssh_ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

with open(SSH_PATH, 'r', errors='ignore') as f:
    for line in f:
        total_ssh_lines += 1
        # Time
        m = ssh_time_pattern.match(line)
        if m:
            month, day, time_str = m.groups()
            sec_key = f"{month} {day} {time_str}"
            ssh_seconds[sec_key] += 1
            if not ssh_timeline or ssh_timeline[-1] != sec_key:
                ssh_timeline.append(sec_key)
        # IP
        ips = ssh_ip_pattern.findall(line)
        for ip in ips:
            ssh_ips[ip] += 1

ssh_rates = list(ssh_seconds.values())
ssh_time_series = [ssh_seconds[k] for k in ssh_timeline]

print(f"[+] OpenSSH: {total_ssh_lines} logs, {len(ssh_rates)} segundos únicos. Taxa máx: {max(ssh_rates)} logs/s")

# ----------------------------------------------------
# PLOT 1: Distribuição de Frequência de Logs/Segundo (Comparativo)
# ----------------------------------------------------
print("[-] Gerando Plot 1: Distribuição de Frequência...")
fig, axes = plt.subplots(1, 2, figsize=(15, 6))

# Plot HDFS (com escala logarítmica no eixo X para acomodar a variação de 1 a 5000)
sns.histplot(hdfs_rates, bins=50, log_scale=(True, False), ax=axes[0], color="#2b5c8f", kde=True)
axes[0].set_title("HDFS - Distribuição de Logs/Segundo", pad=15)
axes[0].set_xlabel("Logs por Segundo (Escala Log)")
axes[0].set_ylabel("Frequência (Segundos)")
axes[0].axvline(np.mean(hdfs_rates), color="#e056fd", linestyle="--", linewidth=2, 
                label=f"Média: {np.mean(hdfs_rates):.1f}/s")
axes[0].axvline(np.median(hdfs_rates), color="#ff7979", linestyle="-.", linewidth=2, 
                label=f"Mediana: {np.median(hdfs_rates):.0f}/s")
axes[0].legend()

# Plot OpenSSH (escala linear simples pois a taxa varia de 1 a 16)
sns.histplot(ssh_rates, bins=16, ax=axes[1], color="#e17055", kde=True)
axes[1].set_title("OpenSSH - Distribuição de Logs/Segundo", pad=15)
axes[1].set_xlabel("Logs por Segundo")
axes[1].set_ylabel("Frequência (Segundos)")
axes[1].axvline(np.mean(ssh_rates), color="#8e44ad", linestyle="--", linewidth=2, 
                label=f"Média: {np.mean(ssh_rates):.1f}/s")
axes[1].axvline(np.median(ssh_rates), color="#27ae60", linestyle="-.", linewidth=2, 
                label=f"Mediana: {np.median(ssh_rates):.0f}/s")
axes[1].legend()

plt.tight_layout()
fig.savefig(os.path.join(OUTPUT_DIR, "log_rate_distribution.png"), dpi=300)
plt.close(fig)
print(f"[+] Gráfico salvo: {OUTPUT_DIR}/log_rate_distribution.png")

# ----------------------------------------------------
# PLOT 2: Linha do Tempo de Exemplo (Temporal Timeline)
# Comparar uma janela de 2 horas (7200 segundos) de atividade para ambos
# ----------------------------------------------------
print("[-] Gerando Plot 2: Linha do Tempo Temporal...")
fig, axes = plt.subplots(2, 1, figsize=(15, 10), sharex=False)

window_size = 7200  # 2 horas
hdfs_slice = hdfs_time_series[20000:20000+window_size] if len(hdfs_time_series) > 20000+window_size else hdfs_time_series[:window_size]
ssh_slice = ssh_time_series[10000:10000+window_size] if len(ssh_time_series) > 10000+window_size else ssh_time_series[:window_size]

axes[0].plot(hdfs_slice, color="#2980b9", alpha=0.8, linewidth=1.5)
axes[0].set_title("HDFS - Comportamento Temporal dos Logs (Janela de 2 horas)", pad=10)
axes[0].set_ylabel("Logs/Segundo")
axes[0].set_xlabel("Tempo (Segundos)")
# Destacar o pico
max_idx = np.argmax(hdfs_slice)
axes[0].annotate(f"Pico Repentino ({hdfs_slice[max_idx]} logs/s)", 
                 xy=(max_idx, hdfs_slice[max_idx]), 
                 xytext=(max_idx + 300, hdfs_slice[max_idx] - 200),
                 arrowprops=dict(facecolor='black', shrink=0.08, width=1, headwidth=6))

axes[1].plot(ssh_slice, color="#e67e22", alpha=0.8, linewidth=1.5)
axes[1].set_title("OpenSSH - Comportamento Temporal dos Logs (Janela de 2 horas)", pad=10)
axes[1].set_ylabel("Logs/Segundo")
axes[1].set_xlabel("Tempo (Segundos)")

plt.tight_layout()
fig.savefig(os.path.join(OUTPUT_DIR, "log_rate_timeline.png"), dpi=300)
plt.close(fig)
print(f"[+] Gráfico salvo: {OUTPUT_DIR}/log_rate_timeline.png")

# ----------------------------------------------------
# PLOT 3: Concentração de Logs por IP no OpenSSH (Justificativa XDP)
# ----------------------------------------------------
print("[-] Gerando Plot 3: Concentração de IPs no OpenSSH...")
top_n = 10
top_ips = ssh_ips.most_common(top_n)
ips_names = [ip for ip, _ in top_ips]
ips_counts = [count for _, count in top_ips]

# Calcular a porcentagem em relação ao total de logs com IPs
total_ip_logs = sum(ssh_ips.values())
ips_pcts = [(count / total_ssh_lines) * 100 for count in ips_counts]

fig, ax1 = plt.subplots(figsize=(12, 6))

color = '#1dd1a1'
# Barplot
bars = sns.barplot(x=ips_names, y=ips_counts, ax=ax1, palette="flare_r", hue=ips_names, legend=False)
ax1.set_title("OpenSSH - Top 10 IPs Geradores de Logs (Ataques Brute-Force)", pad=15)
ax1.set_xlabel("Endereço IP do Atacante")
ax1.set_ylabel("Contagem de Logs (Volume de Ataque)", color="#2c3e50")
ax1.tick_params(axis='y', labelcolor="#2c3e50")
ax1.set_xticks(range(len(ips_names)))
ax1.set_xticklabels(ips_names, rotation=30, ha="right")

# Adicionar porcentagem no topo das barras
for bar, pct in zip(bars.patches, ips_pcts):
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2.0, height + 1000, 
             f"{pct:.1f}%", ha='center', va='bottom', fontsize=10, fontweight='bold')

plt.tight_layout()
fig.savefig(os.path.join(OUTPUT_DIR, "ssh_ip_distribution.png"), dpi=300)
plt.close(fig)
print(f"[+] Gráfico salvo: {OUTPUT_DIR}/ssh_ip_distribution.png")

print("\n[🎉] Todos os gráficos foram gerados e salvos com sucesso!")
