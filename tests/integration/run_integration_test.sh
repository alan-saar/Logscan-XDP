#!/bin/bash
set -euo pipefail

# Configuração de cores para um output "WOW"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # Sem cor

# Valores padrões
NO_EBPF=false
RATE=1000
PARSER="miope"
OUTPUT_CSV="results/data/ebpf_accelerated.csv"

# Parse de argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-ebpf)
            NO_EBPF=true
            shift
            ;;
        --rate)
            RATE="$2"
            shift 2
            ;;
        --parser)
            PARSER="$2"
            shift 2
            ;;
        --output)
            OUTPUT_CSV="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}[❌] Opção desconhecida: $1${NC}"
            echo "Uso: $0 [--no-ebpf] [--rate <taxa>] [--parser <miope|drain3>] [--output <caminho_csv>]"
            exit 1
            ;;
    esac
done

# Ajusta o output padrão
if [ "$OUTPUT_CSV" = "results/data/ebpf_accelerated.csv" ]; then
    if [ "$PARSER" = "drain3" ]; then
        if [ "$NO_EBPF" = true ]; then
            OUTPUT_CSV="results/data/udp_drain3_controlled.csv"
        else
            OUTPUT_CSV="results/data/udp_drain3_ebpf.csv"
        fi
    elif [ "$NO_EBPF" = true ]; then
        OUTPUT_CSV="results/data/udp_no_ebpf.csv"
    fi
fi

echo -e "${CYAN}=================================================="
echo -e "🚀 INICIANDO PIPELINE DE AUTOMACÃO: LOGSCAN-XDP"
echo -e "   Cenário: eBPF=$([ "$NO_EBPF" = true ] && echo "OFF" || echo "ON") | Parser=${PARSER} | Rate=${RATE} logs/s | Output=${OUTPUT_CSV}"
echo -e "==================================================${NC}"

# Obtém a raiz do projeto de forma dinâmica (um nível acima de tests/integration)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${PROJECT_ROOT}"

# 1. Compila o eBPF localmente (somente se não for desativado)
if [ "$NO_EBPF" = false ]; then
    echo -e "\n${BLUE}[*] Passo 1: Compilando eBPF CO-RE localmente...${NC}"
    make
else
    echo -e "\n${BLUE}[*] Passo 1: Pulando compilação do eBPF (modo --no-ebpf)...${NC}"
fi

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
MAIN_ARGS=""
if [ "$NO_EBPF" = true ]; then
    MAIN_ARGS="--no-ebpf"
fi
MAIN_ARGS="${MAIN_ARGS} --parser ${PARSER} --output /app/${OUTPUT_CSV}"

echo -e "\n${BLUE}[*] Passo 5: Inicializando o Daemon Orquestrador (DeepLog) com args: ${MAIN_ARGS}...${NC}"
sudo podman exec -d clab-logscan-lab-victim_server sh -c "python3 -u /app/src/main.py ${MAIN_ARGS} > /app/orchestrator.log 2>&1"

echo -e "${YELLOW}[!] Aguardando 8s para o modelo LSTM carregar e iniciar...${NC}"
sleep 8

# Verifica se o orquestrador permaneceu ativo
if ! sudo podman exec clab-logscan-lab-victim_server ps aux | grep -v grep | grep -q "main.py"; then
    echo -e "${RED}[❌] Erro: O Daemon Orquestrador finalizou inesperadamente! Exibindo logs do orchestrator.log:${NC}"
    sudo podman exec clab-logscan-lab-victim_server cat /app/orchestrator.log || true
    # Destrói o lab e sai
    sudo containerlab destroy -t tests/integration/containerlab.yml -r podman || true
    exit 1
fi

# 6. Dispara a Replay de Tráfego no Nó Atacante
echo -e "\n${BLUE}[*] Passo 6: Disparando tráfego de rede UDP (Rate Limit: ${RATE} logs/s)...${NC}"
sudo podman exec clab-logscan-lab-traffic_generator python3 /app/tests/integration/traffic_generator.py --rate "${RATE}"

# 7. Aguarda o processamento do Orquestrador finalizar
echo -e "\n${BLUE}[*] Passo 7: Aguardando término do processamento da IA...${NC}"
while sudo podman exec clab-logscan-lab-victim_server ps aux | grep -v grep | grep -q "main.py"; do
    sleep 3
done

# 8. Exibe as métricas consolidadas salvas no CSV
echo -e "\n${GREEN}=================================================="
echo -e "📊 MÉTRICAS CIENTÍFICAS EXPERIMENTAIS CONSOLIDADAS:"
echo -e "==================================================${NC}"
if [ -f "${OUTPUT_CSV}" ]; then
    cat "${OUTPUT_CSV}"
else
    echo -e "${RED}[❌] Erro: Arquivo de resultados ${OUTPUT_CSV} não foi encontrado!${NC}"
fi

# 9. Destrói o laboratório para cleanup da máquina
echo -e "\n${BLUE}[*] Passo 9: Descarregando e limpando infraestrutura do laboratório...${NC}"
sudo containerlab destroy -t tests/integration/containerlab.yml -r podman

echo -e "\n${GREEN}[✅] Pipeline de testes automatizado executado com sucesso!${NC}"
