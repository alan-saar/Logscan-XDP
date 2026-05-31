#!/bin/bash
# ------------------------------------------------------------------
# Script de Automação Científica: Reprodução de Experimentos Logscan-XDP
# Finalidade: 
#   1. Compila o eBPF localmente.
#   2. Inicializa a infraestrutura de rede isolada via Containerlab e Podman.
#   3. Resolve todas as dependências de rede e sistema dentro do contêiner.
#   4. Prepara o receptor e orquestrador no User Space (DeepLog LSTM CPU).
#   5. Injeta o tráfego HDFS sob taxa controlada para evitar perdas (Cenário A).
#   6. Coleta e consolida as métricas oficiais de acurácia e telemetria de hardware.
#   7. Limpa a infraestrutura ao término.
# ------------------------------------------------------------------

set -euo pipefail

# Configuração de cores para um output "WOW"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # Sem cor

echo -e "${CYAN}=================================================="
echo -e "🚀 INICIANDO PIPELINE DE AUTOMACÃO: LOGSCAN-XDP"
echo -e "==================================================${NC}"

# Obtém a raiz do projeto de forma dinâmica (um nível acima de tests/integration)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${PROJECT_ROOT}"

# 1. Compila o eBPF localmente
echo -e "\n${BLUE}[*] Passo 1: Compilando eBPF CO-RE localmente...${NC}"
make

# 2. Levanta a topologia do laboratório
echo -e "\n${BLUE}[*] Passo 2: Inicializando topologia no Containerlab (Podman)...${NC}"
sudo containerlab destroy -t tests/integration/containerlab.yml -r podman || true
sudo containerlab deploy -t tests/integration/containerlab.yml -r podman

# 3. Cria compatibilidade de diretórios dentro dos contêineres
echo -e "\n${BLUE}[*] Passo 3: Configurando links de compatibilidade de caminhos...${NC}"
sudo podman exec clab-logscan-lab-victim_server mkdir -p /home/saar/code/mestrado
sudo podman exec clab-logscan-lab-victim_server ln -sf /app /home/saar/code/mestrado/logscan-xdp
sudo podman exec clab-logscan-lab-traffic_generator mkdir -p /home/saar/code/mestrado
sudo podman exec clab-logscan-lab-traffic_generator ln -sf /app /home/saar/code/mestrado/logscan-xdp

# 4. Instala dependências Python no Nó Vítima
echo -e "\n${BLUE}[*] Passo 4: Instalando dependências de IA no victim_server...${NC}"
sudo podman exec clab-logscan-lab-victim_server pip3 install psutil drain3 --break-system-packages
sudo podman exec clab-logscan-lab-victim_server pip3 install torch --index-url https://download.pytorch.org/whl/cpu --break-system-packages

# 5. Inicia o Orquestrador no Nó Vítima (User Space Daemon)
echo -e "\n${BLUE}[*] Passo 5: Inicializando o Daemon Orquestrador (DeepLog)...${NC}"
# Roda em background de forma desmembrada (-d) com saída desbufferizada
sudo podman exec -d clab-logscan-lab-victim_server python3 -u /app/src/main.py

echo -e "${YELLOW}[!] Aguardando 8s para o modelo LSTM carregar e o eBPF acoplar no Kernel...${NC}"
sleep 8

# 6. Dispara a Replay de Tráfego no Nó Atacante (Cenário Controlado)
echo -e "\n${BLUE}[*] Passo 6: Disparando tráfego de rede UDP (Cenário Controlado: 1.000 logs/s)...${NC}"
sudo podman exec clab-logscan-lab-traffic_generator python3 /app/tests/integration/traffic_generator.py --rate 1000

# 7. Aguarda o processamento do Orquestrador finalizar
echo -e "\n${BLUE}[*] Passo 7: Aguardando término do processamento da IA...${NC}"
while sudo podman exec clab-logscan-lab-victim_server ps aux | grep -v grep | grep -q "main.py"; do
    sleep 3
done

# 8. Exibe as métricas consolidadas salvas no CSV
echo -e "\n${GREEN}=================================================="
echo -e "📊 MÉTRICAS CIENTÍFICAS EXPERIMENTAIS CONSOLIDADAS:"
echo -e "==================================================${NC}"
if [ -f "results/data/ebpf_accelerated.csv" ]; then
    cat results/data/ebpf_accelerated.csv
else
    echo -e "${RED}[❌] Erro: Arquivo de resultados ebpf_accelerated.csv não foi encontrado!${NC}"
fi

# 9. Destrói o laboratório para cleanup da máquina
echo -e "\n${BLUE}[*] Passo 8: Descarregando e limpando infraestrutura do laboratório...${NC}"
sudo containerlab destroy -t tests/integration/containerlab.yml -r podman

echo -e "\n${GREEN}[✅] Pipeline de testes automatizado executado com sucesso!${NC}"
