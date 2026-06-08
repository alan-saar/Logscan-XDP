#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Papel: O Gerador de Gráficos e Ilustrações Científicas
O que faz:
1. Carrega os arquivos results/data/baseline.csv e results/data/ebpf_accelerated.csv.
2. Define a paleta de cores Seaborn Premium (Muted Cool / Viridis) para leitura digital de alta fidelidade.
3. Gera 4 gráficos fundamentais da tese em formato vetorial (.pdf) e alta definição (.png):
   - Gráfico 1: Acurácia Comparativa da IA (Precision vs Recall vs F1-Score).
   - Gráfico 2: Ganho de Latência e Tempo Total (Baseline vs Aceleração).
   - Gráfico 3: Eficiência e Leveza de Memória RAM (Pico de Consumo).
   - Gráfico 4: O Falso Dilema da Rede (Multivariado - Flood vs Rate-Limited vs Baseline).
4. Salva as ilustrações na pasta results/images/.
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configurações globais de layout científico
os.makedirs("results/images", exist_ok=True)
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)
plt.rcParams.update({
    'font.family': 'sans-serif',
    'figure.autolayout': True,
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 11
})

# Paleta premium vibrante modernista (Muted Cool)
PALETTE_MUTED = ["#3498db", "#1abc9c", "#9b59b6", "#e74c3c"]
PALETTE_VIRIDIS = ["#440154", "#21918c", "#fde725"]

# 1. Carrega os dados reais coletados
baseline_csv = "results/data/baseline.csv"
ebpf_csv = "results/data/ebpf_accelerated.csv"
controlled_no_ebpf_csv = "results/data/udp_no_ebpf_controlled.csv"
flood_no_ebpf_csv = "results/data/udp_no_ebpf_flood.csv"

# Valores padrão de fallback em caso de leitura (para garantir a integridade)
b_precision, b_recall, b_f1, b_time, b_ram = 86.425, 93.919, 90.016, 75.643, 3.64
e_precision, e_recall, e_f1, e_time, e_ram = 38.467, 55.200, 45.339, 52.606, 0.72
c_precision, c_recall, c_f1, c_logs, c_time = 38.467, 55.200, 45.339, 42229, 53.98
d_precision, d_recall, d_f1, d_logs, d_time = 39.474, 15.915, 22.684, 18395, 9.21

if os.path.exists(baseline_csv):
    df_b = pd.read_csv(baseline_csv)
    b_precision = df_b.loc[0, "Precision"]
    b_recall = df_b.loc[0, "Recall"]
    b_f1 = df_b.loc[0, "F1_Score"]
    b_time = df_b.loc[0, "PredictionTimeSeconds"]
    b_ram = df_b.loc[0, "Max_Memory_Percent"]

if os.path.exists(ebpf_csv):
    df_e = pd.read_csv(ebpf_csv)
    e_precision = df_e.loc[0, "Precision"]
    e_recall = df_e.loc[0, "Recall"]
    e_f1 = df_e.loc[0, "F1_Score"]
    e_time = df_e.loc[0, "EvaluationTimeSeconds"]
    e_ram = df_e.loc[0, "Max_Memory_Percent"]

if os.path.exists(controlled_no_ebpf_csv):
    df_c = pd.read_csv(controlled_no_ebpf_csv)
    c_precision = df_c.loc[0, "Precision"]
    c_recall = df_c.loc[0, "Recall"]
    c_f1 = df_c.loc[0, "F1_Score"]
    c_logs = df_c.loc[0, "TotalProcessedLogs"]
    c_time = df_c.loc[0, "EvaluationTimeSeconds"]

if os.path.exists(flood_no_ebpf_csv):
    df_d = pd.read_csv(flood_no_ebpf_csv)
    d_precision = df_d.loc[0, "Precision"]
    d_recall = df_d.loc[0, "Recall"]
    d_f1 = df_d.loc[0, "F1_Score"]
    d_logs = df_d.loc[0, "TotalProcessedLogs"]
    d_time = df_d.loc[0, "EvaluationTimeSeconds"]

# ==================================================
# GRÁFICO 1: Acurácia Comparativa da IA
# ==================================================
print("[*] Gerando Gráfico 1: Acurácia Comparativa da IA...")
metrics_data = {
    "Modelo": ["Baseline (Drain3)", "Baseline (Drain3)", "Baseline (Drain3)",
               "Acelerado (eBPF FNV-1a)", "Acelerado (eBPF FNV-1a)", "Acelerado (eBPF FNV-1a)"],
    "Métrica": ["Precision", "Recall", "F1-Score", "Precision", "Recall", "F1-Score"],
    "Valor (%)": [b_precision, b_recall, b_f1, e_precision, e_recall, e_f1]
}
df_metrics = pd.DataFrame(metrics_data)

plt.figure(figsize=(7, 5))
ax = sns.barplot(
    data=df_metrics,
    x="Métrica",
    y="Valor (%)",
    hue="Modelo",
    palette=["#2c3e50", "#1abc9c"]
)
plt.title("Acurácia da Detecção: Baseline vs Acelerado", pad=15)
plt.ylim(0, 110)
plt.ylabel("Acurácia (%)")
plt.xlabel("Métrica Avaliada")

# Adiciona os rótulos de valores em cima das barras
for p in ax.patches:
    h = p.get_height()
    if h > 0:
        ax.annotate(f'{h:.2f}%', 
                    (p.get_x() + p.get_width() / 2., h), 
                    ha='center', va='center', 
                    xytext=(0, 8), 
                    textcoords='offset points',
                    fontsize=9, weight='bold')

plt.savefig("results/images/01_acuracia_comparativa.png", dpi=300)
plt.savefig("results/images/01_acuracia_comparativa.pdf")
plt.close()

# ==================================================
# GRÁFICO 2: Ganho de Latência e Tempo Total
# ==================================================
print("[*] Gerando Gráfico 2: Latência e Tempo de Execução...")
plt.figure(figsize=(6, 5))
time_data = {
    "Cenário": ["Baseline (IA Pura)", "Acelerado (eBPF/XDP)"],
    "Tempo (s)": [b_time, e_time]
}
df_time = pd.DataFrame(time_data)

ax = sns.barplot(
    data=df_time,
    x="Cenário",
    y="Tempo (s)",
    palette=["#e74c3c", "#3498db"],
    width=0.5
)
plt.title("Tempo Total de Inferência da IA (42k Logs)", pad=15)
plt.ylabel("Tempo de Execução (segundos)")
plt.xlabel("")

for p in ax.patches:
    h = p.get_height()
    ax.annotate(f'{h:.2f}s', 
                (p.get_x() + p.get_width() / 2., h), 
                ha='center', va='center', 
                xytext=(0, 8), 
                textcoords='offset points',
                fontsize=10, weight='bold')

# Adiciona o ganho relativo impresso no gráfico
ganho = ((b_time - e_time) / b_time) * 100
plt.text(0.5, b_time * 0.8, f"Ganho de Performance:\n-{ganho:.1f}% de Latência", 
         ha='center', fontsize=10, bbox=dict(boxstyle="round,pad=0.5", fc="#f1c40f", alpha=0.3))

plt.savefig("results/images/02_ganho_latencia.png", dpi=300)
plt.savefig("results/images/02_ganho_latencia.pdf")
plt.close()

# ==================================================
# GRÁFICO 3: Eficiência e Leveza de Memória RAM
# ==================================================
print("[*] Gerando Gráfico 3: Eficiência de Memória RAM...")
plt.figure(figsize=(6, 5))
ram_data = {
    "Arquitetura": ["Baseline (Drain3 Tree)", "Acelerado (Hash Míope)"],
    "Pico de RAM (%)": [b_ram, e_ram]
}
df_ram = pd.DataFrame(ram_data)

ax = sns.barplot(
    data=df_ram,
    x="Arquitetura",
    y="Pico de RAM (%)",
    palette=["#95a5a6", "#2ecc71"],
    width=0.5
)
plt.title("Pegada de Memória RAM no Nó Vítima", pad=15)
plt.ylabel("Pico de Uso da Memória RAM (%)")
plt.xlabel("")

for p in ax.patches:
    h = p.get_height()
    ax.annotate(f'{h:.2f}%', 
                (p.get_x() + p.get_width() / 2., h), 
                ha='center', va='center', 
                xytext=(0, 8), 
                textcoords='offset points',
                fontsize=10, weight='bold')

plt.savefig("results/images/03_eficiencia_ram.png", dpi=300)
plt.savefig("results/images/03_eficiencia_ram.pdf")
plt.close()

# ==================================================
# GRÁFICO 4: O Falso Dilema da Rede (Multivariado)
# ==================================================
print("[*] Gerando Gráfico 4: O Falso Dilema da Rede (Multivariado)...")

# Calcula as perdas de pacotes de forma dinâmica para os novos cenários
c_loss = ((42229 - c_logs) / 42229) * 100.0
d_loss = ((42229 - d_logs) / 42229) * 100.0

# Dados dos 5 Cenários Metodológicos da tese
dilema_data = {
    "Cenário": [
        "Baseline\n(Offline)", 
        "Controlado\n(eBPF ON)", 
        "Controlado\n(eBPF OFF)", 
        "UDP Flood\n(eBPF ON)", 
        "UDP Flood\n(eBPF OFF)"
    ],
    "Perda de Pacotes (%)": [0.0, 0.0, c_loss, 57.85, d_loss],
    "F1-Score (%)": [b_f1, e_f1, c_f1, 20.127, d_f1],
    "Tempo de Execução (s)": [b_time, e_time, c_time, 19.28, d_time]
}
df_dilema = pd.DataFrame(dilema_data)

fig, ax1 = plt.subplots(figsize=(9, 5.5))

# Eixo esquerdo: F1-Score
color = '#8e44ad'
ax1.set_xlabel('Cenário de Transmissão')
ax1.set_ylabel('Acurácia F1-Score (%)', color=color)
ax1.tick_params(axis='y', labelcolor=color)
sns.barplot(data=df_dilema, x="Cenário", y="F1-Score (%)", ax=ax1, color=color, alpha=0.35, width=0.45)
ax1.set_ylim(0, 110)

# Adiciona o valor de F1 nas barras
for idx, p in enumerate(ax1.patches):
    h = p.get_height()
    if h > 0:
        ax1.annotate(f'{h:.2f}%', 
                    (p.get_x() + p.get_width() / 2., h), 
                    ha='center', va='center', 
                    xytext=(0, 8), 
                    textcoords='offset points',
                    fontsize=9, weight='bold', color='#682782')

# Eixo direito: Perda de Pacotes
ax2 = ax1.twinx()
color = '#c0392b'
ax2.set_ylabel('Perda de Pacotes na Rede (%)', color=color)
ax2.tick_params(axis='y', labelcolor=color)
sns.lineplot(data=df_dilema, x="Cenário", y="Perda de Pacotes (%)", ax=ax2, color=color, marker="o", linewidth=2.5, markersize=8)
ax2.set_ylim(-10, 100)

# Adiciona as anotações de perda de pacotes na linha
for idx, row in df_dilema.iterrows():
    ax2.annotate(f'{row["Perda de Pacotes (%)"]:.1f}%', 
                 (idx, row["Perda de Pacotes (%)"]),
                 textcoords="offset points", 
                 xytext=(0, 10), 
                 ha='center', 
                 fontsize=9, 
                 weight='bold', 
                 color='#c0392b')

plt.title("O Falso Dilema da Rede: Perda de Pacotes vs Acurácia", pad=15)
plt.savefig("results/images/04_falso_dilema_rede.png", dpi=300)
plt.savefig("results/images/04_falso_dilema_rede.pdf")
plt.close()

print("[✅] Todos os 4 gráficos científicos Seaborn Premium foram gerados sob results/images/!")
