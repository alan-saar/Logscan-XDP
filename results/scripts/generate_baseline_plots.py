#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finalidade do Arquivo: Gerador de Gráficos Científicos da Baseline (Fase 2.3).
Este script importa os dados experimentais coletados em 'results/data/baseline.csv',
aplica estilos de publicação acadêmica e gera 3 gráficos de alta resolução (300 DPI)
na pasta 'results/images/':
1. Métricas de Acurácia (Precision, Recall, F1-Score).
2. Tempos de Execução (Treinamento com CUDA vs Inferência em User Space).
3. Consumo Pico de Recursos (CPU vs RAM).

"""

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def configure_publication_style():
    """
    Configura o matplotlib e o seaborn com padrões estéticos premium 
    para publicações científicas (paper / dissertação).
    """
    sns.set_theme(style="whitegrid", context="paper")
    plt.rcParams.update({
        'font.family': 'sans-serif',
        'font.size': 11,
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'figure.titlesize': 14,
        'legend.fontsize': 10,
        'savefig.dpi': 300,
        'savefig.bbox': 'tight'
    })

def plot_accuracy_metrics(df, output_path):
    """
    Gera um gráfico de barras premium para as métricas de acurácia da IA (Precision, Recall, F1).
    
    Parâmetros:
    - df (pd.DataFrame): Dataframe contendo as métricas de baseline.
    - output_path (str): Caminho físico para salvar a imagem gerada.
    """
    plt.figure(figsize=(6, 5))
    
    metrics = {
        'Precision': df['Precision'].iloc[0],
        'Recall': df['Recall'].iloc[0],
        'F1-Score': df['F1_Score'].iloc[0]
    }
    
    # Paleta de cores sofisticada (Esmeralda, Azul Aço, Coral)
    colors = ['#1b9e77', '#377eb8', '#e41a1c']
    
    bars = plt.bar(metrics.keys(), metrics.values(), color=colors, width=0.5, edgecolor='black', linewidth=0.8)
    
    # Adiciona os valores em cima de cada barra
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2.0, 
            height + 1.5, 
            f'{height:.3f}%', 
            ha='center', 
            va='bottom', 
            fontweight='bold',
            color='#333333'
        )
        
    plt.ylabel('Porcentagem (%)', fontweight='bold')
    plt.title('Métricas de Acurácia da IA (DeepLog Baseline)', fontweight='bold', pad=15)
    plt.ylim(0, 110)
    
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"[📊] Gráfico de Métricas salvo em: {output_path}")

def plot_execution_times(df, output_path):
    """
    Gera um gráfico comparativo de tempo demonstrando a disparidade
    entre o treinamento (com CUDA) e a inferência pura (User Space).
    
    Parâmetros:
    - df (pd.DataFrame): Dataframe contendo as métricas de baseline.
    - output_path (str): Caminho físico para salvar a imagem gerada.
    """
    plt.figure(figsize=(6, 5))
    
    times = {
        'Treinamento\n(CUDA - 15 Épocas)': df['TrainingTimeSeconds'].iloc[0],
        'Inferência de Teste\n(Espaço de Usuário)': df['PredictionTimeSeconds'].iloc[0]
    }
    
    colors = ['#4daf4a', '#ff7f00']
    bars = plt.bar(times.keys(), times.values(), color=colors, width=0.4, edgecolor='black', linewidth=0.8)
    
    # Adiciona rótulos de tempo formatados em cima das barras
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2.0, 
            height + (max(times.values()) * 0.02), 
            f'{height:.2f}s', 
            ha='center', 
            va='bottom', 
            fontweight='bold',
            color='#333333'
        )
        
    plt.ylabel('Tempo em Segundos (s)', fontweight='bold')
    plt.title('Diferença de Tempo: Treino GPU vs Inferência CPU', fontweight='bold', pad=15)
    plt.ylim(0, max(times.values()) * 1.15)
    
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"[📊] Gráfico de Tempos salvo em: {output_path}")

def plot_resource_usage(df, output_path):
    """
    Gera um gráfico de barras comparativo do uso de CPU e RAM no host.
    
    Parâmetros:
    - df (pd.DataFrame): Dataframe contendo as métricas de baseline.
    - output_path (str): Caminho físico para salvar a imagem gerada.
    """
    fig, ax1 = plt.subplots(figsize=(6, 5))
    
    cpu_peak = df['Max_CPU_Percent'].iloc[0]
    mem_peak = df['Max_Memory_Percent'].iloc[0]
    
    # Plota a CPU no eixo esquerdo (y1)
    color_cpu = '#377eb8'
    ax1.set_ylabel('Pico de Uso da CPU (%)', color=color_cpu, fontweight='bold')
    bar_cpu = ax1.bar(['Pico CPU'], [cpu_peak], color=color_cpu, width=0.3, label='Pico CPU', edgecolor='black', linewidth=0.8)
    ax1.tick_params(axis='y', labelcolor=color_cpu)
    ax1.set_ylim(0, max(cpu_peak * 1.15, 100))
    
    # Adiciona rótulo numérico no topo da barra de CPU
    for bar in bar_cpu:
        height = bar.get_height()
        ax1.text(
            bar.get_x() + bar.get_width() / 2.0, 
            height + (cpu_peak * 0.02), 
            f'{height:.1f}%', 
            ha='center', 
            va='bottom', 
            fontweight='bold',
            color=color_cpu
        )
    
    # Cria o eixo direito (y2) compartilhado para a RAM
    ax2 = ax1.twinx()
    color_mem = '#984ea3'
    ax2.set_ylabel('Pico de Uso da RAM (%)', color=color_mem, fontweight='bold')
    bar_mem = ax2.bar(['Pico RAM'], [mem_peak], color=color_mem, width=0.3, label='Pico RAM', edgecolor='black', linewidth=0.8)
    ax2.tick_params(axis='y', labelcolor=color_mem)
    ax2.set_ylim(0, max(mem_peak * 1.2, 10))
    
    # Adiciona rótulo numérico no topo da barra de RAM
    for bar in bar_mem:
        height = bar.get_height()
        ax2.text(
            bar.get_x() + bar.get_width() / 2.0, 
            height + (max(mem_peak * 0.02, 0.2)), 
            f'{height:.2f}%', 
            ha='center', 
            va='bottom', 
            fontweight='bold',
            color=color_mem
        )
        
    plt.title('Picos de Consumo de Recursos do Sistema', fontweight='bold', pad=15)
    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"[📊] Gráfico de Recursos do Sistema salvo em: {output_path}")

def main():
    base_dir = "/home/saar/code/mestrado/logscan-xdp"
    csv_path = os.path.join(base_dir, "results/data/baseline.csv")
    images_dir = os.path.join(base_dir, "results/images")
    os.makedirs(images_dir, exist_ok=True)
    
    if not os.path.exists(csv_path):
        print(f"[❌] Erro: Arquivo de baseline não localizado em '{csv_path}'. Rode a coleta primeiro!")
        return
        
    print("==================================================")
    print("📈 EXECUTANDO COMPILADOR DE GRÁFICOS CIENTÍFICOS")
    print("==================================================")
    
    df = pd.read_csv(csv_path)
    
    configure_publication_style()
    
    # 1. Plota Acurácia (Precision, Recall, F1)
    plot_accuracy_metrics(df, os.path.join(images_dir, "baseline_metrics.png"))
    
    # 2. Plota Tempos comparativos
    plot_execution_times(df, os.path.join(images_dir, "baseline_time_comparison.png"))
    
    # 3. Plota Uso de CPU / RAM
    plot_resource_usage(df, os.path.join(images_dir, "baseline_resource_usage.png"))
    
    print("==================================================")
    print("[✅] TODOS OS GRÁFICOS GERADOS COM SUCESSO EM results/images/")
    print("==================================================")

if __name__ == "__main__":
    main()
