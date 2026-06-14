#!/bin/bash
# -*- coding: utf-8 -*-

# tests/labvm/run_experiments.sh
# Script de automação interativa para rodar os experimentos na VM Vítima (192.168.122.100).
# Coordena as rodadas científicas, orientando o usuário sobre o comando a rodar na VM Atacante.

# Cores para o terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Caminhos locais
BASE_DIR="/home/saar/code/mestrado/logscan-xdp"
RECEIVER_SCRIPT="${BASE_DIR}/tests/labvm/receiver_vm.py"
OUTPUT_CSV="${BASE_DIR}/tests/labvm/results_vm.csv"

# Função para exibir banner bonito
show_banner() {
    clear
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}🚀  LOGSCAN-XDP - ORQUESTRADOR DE EXPERIMENTOS EM MÁQUINAS VIRTUAIS   ${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "Este script executa sequencialmente 7 rodadas experimentais para avaliar"
    echo -e "o comportamento do sistema sob taxas de rede UDP variáveis e com/sem eBPF."
    echo -e "Os resultados consolidados serão gravados em:"
    echo -e "  -> ${YELLOW}${OUTPUT_CSV}${NC}"
    echo -e "${BLUE}======================================================================${NC}\n"
}

# Função para verificar dependências básicas
check_dependencies() {
    echo -e "[*] Verificando ambiente na VM Vítima..."
    if [ ! -d "$BASE_DIR" ]; then
        echo -e "${RED}[❌] Erro: Diretório base não encontrado em $BASE_DIR${NC}"
        exit 1
    fi
    if [ ! -f "$RECEIVER_SCRIPT" ]; then
        echo -e "${RED}[❌] Erro: Script receptor não encontrado em $RECEIVER_SCRIPT${NC}"
        exit 1
    fi
    
    # Verifica Python3
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[❌] Erro: python3 não está instalado.${NC}"
        exit 1
    fi

    # Verifica bpftool se não for rodar com --no-ebpf
    if ! command -v bpftool &> /dev/null; then
        echo -e "${YELLOW}[⚠️] Aviso: bpftool não encontrado no PATH global. Certifique-se de que está instalado ou fixado no roteiro.${NC}"
    fi

    echo -e "${GREEN}[✅] Ambiente inicial validado com sucesso!${NC}\n"
    sleep 1.5
}

# Função para executar uma rodada experimental
run_round() {
    local round_num=$1
    local scenario_name=$2
    local parser_type=$3
    local no_ebpf_flag=$4 # "true" ou "false"
    local attacker_rate=$5 # "0" (Flood) ou taxa numérica

    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BOLD}RODADA ${round_num}/7: ${scenario_name}${NC}"
    echo -e "${BLUE}----------------------------------------------------------------------${NC}"
    echo -e "  - Algoritmo de Parser : ${YELLOW}${parser_type}${NC}"
    echo -e "  - Aceleração eBPF     : $([ "$no_ebpf_flag" = "true" ] && echo -e "${RED}DESATIVADA (Baseline)" || echo -e "${GREEN}ATIVA (Kernel Space)")"
    echo -e "  - Taxa do Atacante    : $([ "$attacker_rate" = "0" ] && echo -e "${RED}Flood (Velocidade Máxima)" || echo -e "${YELLOW}${attacker_rate} logs/s")"
    echo -e "${BLUE}----------------------------------------------------------------------${NC}"
    
    echo -e "\n${BOLD}👉 INSTRUÇÕES PARA A VM ATACANTE (192.168.122.101):${NC}"
    echo -e "Abra um terminal na VM Atacante e prepare o comando abaixo (NÃO execute ainda):"
    if [ "$attacker_rate" = "0" ]; then
        echo -e "  ${GREEN}python3 sender_vm.py --ip 192.168.122.100 --rate 0${NC}"
    else
        echo -e "  ${GREEN}python3 sender_vm.py --ip 192.168.122.100 --rate ${attacker_rate}${NC}"
    fi
    echo ""

    read -p "Aperte [ENTER] para INICIAR o receptor na Vítima e então execute o comando no Atacante..."
    
    echo -e "\n[*] Iniciando receptor..."
    
    # Prepara o comando de execução
    local cmd="python3 ${RECEIVER_SCRIPT} --parser ${parser_type} --scenario \"${scenario_name}\" --output \"${OUTPUT_CSV}\""
    if [ "$no_ebpf_flag" = "true" ]; then
        cmd="${cmd} --no-ebpf"
    fi

    # Executa com sudo se eBPF estiver ativo para permitir carregamento do kprobe
    if [ "$no_ebpf_flag" = "false" ]; then
        echo -e "${YELLOW}[*] Executando com sudo para carregamento do filtro eBPF...${NC}"
        sudo -E python3 ${RECEIVER_SCRIPT} --parser ${parser_type} --scenario "${scenario_name}" --output "${OUTPUT_CSV}"
    else
        python3 ${RECEIVER_SCRIPT} --parser ${parser_type} --scenario "${scenario_name}" --output "${OUTPUT_CSV}" --no-ebpf
    fi

    echo -e "${GREEN}[✅] Rodada ${round_num} concluída!${NC}"
    echo -e "Aguardando 3 segundos para estabilização da rede...\n"
    sleep 3
}

# --- EXECUÇÃO PRINCIPAL ---
show_banner
check_dependencies

# Pergunta para iniciar
read -p "Deseja iniciar a bateria de testes? (s/n): " confirm
if [[ ! "$confirm" =~ ^[Ss]$ ]]; then
    echo -e "${RED}[*] Cancelado pelo usuário.${NC}"
    exit 0
fi

# Rodada 1: Baseline UDP Flood (Miope, Sem eBPF, Flood)
run_round 1 "Baseline_UDP_Flood" "miope" "true" 0

# Rodada 2: Baseline UDP Controlado 1000 (Miope, Sem eBPF, 1000 logs/s)
run_round 2 "Baseline_UDP_Control_1000" "miope" "true" 1000

# Rodada 3: Baseline UDP Controlado 100 (Miope, Sem eBPF, 100 logs/s)
run_round 3 "Baseline_UDP_Control_100" "miope" "true" 100

# Rodada 4: Drain3 UDP Flood (Drain3, Sem eBPF, Flood)
run_round 4 "Drain3_UDP_Flood" "drain3" "true" 0

# Rodada 5: Drain3 UDP Controlado 500 (Drain3, Sem eBPF, 500 logs/s)
run_round 5 "Drain3_UDP_Control_500" "drain3" "true" 500

# Rodada 6: Míope + eBPF Flood (Miope, Com eBPF, Flood)
run_round 6 "MIOPE_eBPF_Flood" "miope" "false" 0

# Rodada 7: Míope + eBPF Controlado 1000 (Miope, Com eBPF, 1000 logs/s)
run_round 7 "MIOPE_eBPF_Control_1000" "miope" "false" 1000

echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}🎉  FIM DA BATERIA DE TESTES! TODOS OS RESULTADOS FORAM GRAVADOS EM:   ${NC}"
echo -e "    -> ${YELLOW}${OUTPUT_CSV}${NC}"
echo -e "${GREEN}======================================================================${NC}"
exit 0
