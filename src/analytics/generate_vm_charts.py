#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
tests/analytics/generate_vm_charts.py
Papel: Gerador de ilustrações científicas de alta fidelidade para os testes em Máquinas Virtuais (VMs).
Lê o arquivo tests/labvm/results_vm.csv e plota gráficos Seaborn Premium.
Salva os arquivos em results/images/vm/.
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Cria os diretórios para salvar as imagens das VMs
os.makedirs("results/images/vm", exist_ok=True)

# Configurações globais de layout científico
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)
plt.rcParams.update({
    'font.family': 'sans-serif',
    'figure.autolayout': True,
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10
})

# Caminho para o CSV de resultados da VM
CSV_PATH = "tests/labvm/results_vm.csv"

def load_data():
    if not os.path.exists(CSV_PATH):
        print(f"[❌] Erro: Arquivo de resultados {CSV_PATH} não encontrado.")
        return None
    df = pd.read_csv(CSV_PATH)
    print(f"[✅] Carregados {len(df)} cenários do CSV de resultados da VM.")
    return df

def generate_accuracy_chart(df):
    """
    Gera gráfico comparando Precision, Recall e F1-Score entre os cenários em VM.
    """
    print("[*] Gerando Gráfico: Acurácia Comparativa da IA na VM...")
    
    # Filtra cenários chaves para visualização de acurácia
    # Usamos o baseline puro (offline), controlado com míope e controlado com drain3
    scenarios_of_interest = [
        "Baseline_UDP_Control_1000",
        "Drain3_UDP_Control_500",
        "MIOPE_eBPF_Control_1000",
        "MIOPE_eBPF_Flood"
    ]
    
    df_filtered = df[df["Scenario"].isin(scenarios_of_interest)].copy()
    
    # Mapeia nomes mais amigáveis para os cenários no gráfico
    name_map = {
        "Baseline_UDP_Control_1000": "Míope Controlado (Sem eBPF)",
        "Drain3_UDP_Control_500": "Drain3 Controlado (Sem eBPF)",
        "MIOPE_eBPF_Control_1000": "Míope Controlado (Com eBPF)",
        "MIOPE_eBPF_Flood": "Míope eBPF Flood (Com perdas/filtros)"
    }
    df_filtered["Cenário"] = df_filtered["Scenario"].map(name_map)
    
    # Transforma em formato longo para o Seaborn (melt)
    melted = df_filtered.melt(
        id_vars=["Cenário"], 
        value_vars=["Precision", "Recall", "F1_Score"], 
        var_name="Métrica", 
        value_name="Valor"
    )
    
    # Mapeia nomes de métricas
    melted["Métrica"] = melted["Métrica"].replace("F1_Score", "F1-Score")
    
    plt.figure(figsize=(9, 5.5))
    ax = sns.barplot(
        data=melted,
        x="Métrica",
        y="Valor",
        hue="Cenário",
        palette=["#34495e", "#3498db", "#2ecc71", "#e74c3c"]
    )
    plt.title("Métricas de Acurácia da IA nas Máquinas Virtuais", pad=15)
    plt.ylim(0, 115)
    plt.ylabel("Porcentagem (%)")
    plt.xlabel("Métrica Avaliada")
    plt.legend(title="Configuração do Cenário (VM)", bbox_to_anchor=(0.5, -0.15), loc='upper center', ncol=2)
    
    # Adiciona rótulos de dados
    for p in ax.patches:
        h = p.get_height()
        if h > 0:
            ax.annotate(f'{h:.1f}%', 
                        (p.get_x() + p.get_width() / 2., h), 
                        ha='center', va='center', 
                        xytext=(0, 8), 
                        textcoords='offset points',
                        fontsize=8, weight='bold')
            
    plt.savefig("results/images/vm/vm_01_acuracia_comparativa.png", dpi=300, bbox_inches='tight')
    plt.savefig("results/images/vm/vm_01_acuracia_comparativa.pdf", bbox_inches='tight')
    plt.close()

def generate_duration_chart(df):
    """
    Compara o tempo total de inferência/duração entre os cenários.
    """
    print("[*] Gerando Gráfico: Tempo de Processamento da IA na VM...")
    
    # Filtra cenários rodados com taxa controlada (1000 logs/s no míope e 500 logs/s no drain3)
    # E adiciona o flood correspondente para ver a latência sob fluxo constante
    scenarios_of_interest = [
        "Baseline_UDP_Control_1000",
        "MIOPE_eBPF_Control_1000",
        "Drain3_UDP_Control_500"
    ]
    
    df_filtered = df[df["Scenario"].isin(scenarios_of_interest)].copy()
    
    name_map = {
        "Baseline_UDP_Control_1000": "Míope (Sem eBPF)\n1000 logs/s",
        "MIOPE_eBPF_Control_1000": "Míope (Com eBPF)\n1000 logs/s",
        "Drain3_UDP_Control_500": "Drain3 (Sem eBPF)\n500 logs/s"
    }
    df_filtered["Cenário"] = df_filtered["Scenario"].map(name_map)
    
    plt.figure(figsize=(7, 5))
    ax = sns.barplot(
        data=df_filtered,
        x="Cenário",
        y="DurationSeconds",
        palette=["#7f8c8d", "#2ecc71", "#e67e22"],
        width=0.5
    )
    plt.title("Tempo Total de Processamento da IA nas VMs (42k logs)", pad=15)
    plt.ylabel("Duração Total (segundos)")
    plt.xlabel("")
    plt.ylim(0, max(df_filtered["DurationSeconds"]) * 1.15)
    
    for p in ax.patches:
        h = p.get_height()
        ax.annotate(f'{h:.2f}s', 
                    (p.get_x() + p.get_width() / 2., h), 
                    ha='center', va='center', 
                    xytext=(0, 8), 
                    textcoords='offset points',
                    fontsize=10, weight='bold')
        
    plt.savefig("results/images/vm/vm_02_duracao_processamento.png", dpi=300)
    plt.savefig("results/images/vm/vm_02_duracao_processamento.pdf")
    plt.close()

def generate_network_loss_dilemma_chart(df):
    """
    Gráfico de duas escalas correlacionando Perda Física Aplicacional (%) com o F1-Score da IA.
    Visualiza as rodadas de tráfego máximo (Flood) e controladas das VMs.
    """
    print("[*] Gerando Gráfico: O Falso Dilema da Rede nas VMs...")
    
    # Seleciona cenários específicos para demonstrar o dilema
    scenarios_of_interest = [
        "Baseline_UDP_Control_1000",
        "Baseline_UDP_Flood",
        "Drain3_UDP_Control_500",
        "Drain3_UDP_Flood",
        "MIOPE_eBPF_Flood"
    ]
    
    df_filtered = df[df["Scenario"].isin(scenarios_of_interest)].copy()
    
    name_map = {
        "Baseline_UDP_Control_1000": "Controlado\n(Míope)",
        "Baseline_UDP_Flood": "Flood\n(Míope)",
        "Drain3_UDP_Control_500": "Controlado\n(Drain3)",
        "Drain3_UDP_Flood": "Flood\n(Drain3)",
        "MIOPE_eBPF_Flood": "Flood\n(eBPF)"
    }
    df_filtered["Cenário"] = df_filtered["Scenario"].map(name_map)
    
    # Ordena os cenários logicamente
    df_filtered["order"] = df_filtered["Scenario"].map({
        "Baseline_UDP_Control_1000": 1,
        "Drain3_UDP_Control_500": 2,
        "Baseline_UDP_Flood": 3,
        "Drain3_UDP_Flood": 4,
        "MIOPE_eBPF_Flood": 5
    })
    df_filtered = df_filtered.sort_values("order")
    
    fig, ax1 = plt.subplots(figsize=(9, 5.5))
    
    # Eixo 1 (Esquerda): F1-Score
    color_f1 = '#8e44ad' # Roxo
    ax1.set_xlabel('Cenário de Transmissão nas VMs')
    ax1.set_ylabel('Acurácia F1-Score (%)', color=color_f1)
    ax1.tick_params(axis='y', labelcolor=color_f1)
    
    sns.barplot(
        data=df_filtered, 
        x="Cenário", 
        y="F1_Score", 
        ax=ax1, 
        color=color_f1, 
        alpha=0.35, 
        width=0.45
    )
    ax1.set_ylim(0, 110)
    
    for idx, p in enumerate(ax1.patches):
        h = p.get_height()
        if h > 0:
            ax1.annotate(f'{h:.1f}%', 
                        (p.get_x() + p.get_width() / 2., h), 
                        ha='center', va='center', 
                        xytext=(0, 8), 
                        textcoords='offset points',
                        fontsize=9, weight='bold', color='#682782')
            
    # Eixo 2 (Direita): Perda Aplicacional de logs na Rede
    ax2 = ax1.twinx()
    color_loss = '#c0392b' # Vermelho
    ax2.set_ylabel('Perda Aplicacional de Logs (%)', color=color_loss)
    ax2.tick_params(axis='y', labelcolor=color_loss)
    
    sns.lineplot(
        data=df_filtered, 
        x="Cenário", 
        y="AppLossPercent", 
        ax=ax2, 
        color=color_loss, 
        marker="o", 
        linewidth=2.5, 
        markersize=8
    )
    ax2.set_ylim(-10, 100)
    
    # Adiciona rótulos à linha de perda de pacotes
    for idx, row in df_filtered.reset_index(drop=True).iterrows():
        ax2.annotate(f'{row["AppLossPercent"]:.1f}%', 
                     (idx, row["AppLossPercent"]),
                     textcoords="offset points", 
                     xytext=(0, 10), 
                     ha='center', 
                     fontsize=9, 
                     weight='bold', 
                     color='#c0392b')
        
    plt.title("O Falso Dilema da Rede em VMs: Perda Física vs F1-Score da IA", pad=15)
    plt.savefig("results/images/vm/vm_03_falso_dilema_rede.png", dpi=300)
    plt.savefig("results/images/vm/vm_03_falso_dilema_rede.pdf")
    plt.close()

def main():
    df = load_data()
    if df is not None:
        generate_accuracy_chart(df)
        generate_duration_chart(df)
        generate_network_loss_dilemma_chart(df)
        print("[✅] Todos os gráficos científicos das VMs foram gerados em results/images/vm/!")

if __name__ == "__main__":
    main()
