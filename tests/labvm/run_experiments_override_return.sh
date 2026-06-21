#!/bin/bash
# -*- coding: utf-8 -*-

# tests/labvm/run_experiments_overrride_return.h (ou .sh)
# Script de automação para rodar experimentos eBPF locais utilizando a função de return (override)
# Eliminando totalmente o fator rede para estabelecer um comparativo científico com o Baseline puro.

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
DATASET_PATH="${BASE_DIR}/full_dataset/HDFS/HDFS_test.log"
OUTPUT_DIR="${BASE_DIR}/results/data"
OUTPUT_CSV="${OUTPUT_DIR}/override_return.csv"

# Cria pasta de resultados se não existir
mkdir -p "${OUTPUT_DIR}"

# Exibe banner bonito
clear
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}🚀  LOGSCAN-XDP - VALIDAÇÃO LOCAL DE EBPF COM OVERRIDE RETURN         ${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo -e "Executando bateria de testes locais (sem rede) nas VMs para isolar a rede"
echo -e "e quantificar o impacto de performance e acurácia pura do eBPF Override."
echo -e "Os resultados consolidados serão gravados em:"
echo -e "  -> ${YELLOW}${OUTPUT_CSV}${NC}"
echo -e "${BLUE}======================================================================${NC}\n"

# Verifica ambiente
echo -e "[*] Verificando dependências locais..."
if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[❌] Erro: Diretório base não encontrado em $BASE_DIR${NC}"
    exit 1
fi
if [ ! -f "$RECEIVER_SCRIPT" ]; then
    echo -e "${RED}[❌] Erro: Script receptor não encontrado em $RECEIVER_SCRIPT${NC}"
    exit 1
fi
if [ ! -f "$DATASET_PATH" ]; then
    echo -e "${RED}[❌] Erro: Dataset não encontrado em $DATASET_PATH${NC}"
    exit 1
fi

# Define o interpretador Python do virtualenv
python_bin="${BASE_DIR}/.venv-logscan/bin/python3"
if [ ! -f "$python_bin" ]; then
    python_bin="python3"
fi
echo -e "${GREEN}[✅] Utilizando interpretador: $python_bin${NC}\n"

# Função para executar rodada
run_local_round() {
    local round_num=$1
    local scenario_name=$2
    local parser_type=$3
    local no_ebpf_flag=$4 # "true" ou "false"

    echo -e "${BLUE}----------------------------------------------------------------------${NC}"
    echo -e "${BOLD}RODADA ${round_num}/3: ${scenario_name}${NC}"
    echo -e "${BLUE}----------------------------------------------------------------------${NC}"
    echo -e "  - Algoritmo de Parser : ${YELLOW}${parser_type}${NC}"
    echo -e "  - Aceleração eBPF     : $([ "$no_ebpf_flag" = "true" ] && echo -e "${RED}DESATIVADA (Baseline)" || echo -e "${GREEN}ATIVA (bpf_override_return)")"
    echo -e "  - Modo de Execução    : ${CYAN}Local (Bypass de Rede UDP)${NC}"
    echo -e "${BLUE}----------------------------------------------------------------------${NC}"

    # Compila o eBPF localmente para garantir o binário sem DISABLE_OVERRIDE
    if [ "$no_ebpf_flag" = "false" ]; then
        echo -e "[*] Recompilando eBPF CO-RE para garantir suporte a Override Return..."
        (cd "${BASE_DIR}" && make clean && make)
    fi

    echo -e "\n[*] Iniciando processamento..."
    
    if [ "$no_ebpf_flag" = "false" ]; then
        echo -e "${YELLOW}[*] Executando com sudo para carregamento do eBPF com override no Kernel...${NC}"
        sudo -E "$python_bin" "${RECEIVER_SCRIPT}" \
            --parser "${parser_type}" \
            --scenario "${scenario_name}" \
            --output "${OUTPUT_CSV}" \
            --local-file "${DATASET_PATH}"
    else
        "$python_bin" "${RECEIVER_SCRIPT}" \
            --parser "${parser_type}" \
            --scenario "${scenario_name}" \
            --output "${OUTPUT_CSV}" \
            --no-ebpf \
            --local-file "${DATASET_PATH}"
    fi

    echo -e "${GREEN}[✅] Rodada ${round_num} concluída!${NC}\n"
    sleep 2
}

# Pergunta para iniciar
read -p "Deseja iniciar a bateria de testes locais com Override Return? (s/n): " confirm
if [[ ! "$confirm" =~ ^[Ss]$ ]]; then
    echo -e "${RED}[*] Cancelado pelo usuário.${NC}"
    exit 0
fi

# Limpa arquivo de resultados anterior se existir para evitar confusão de dados
rm -f "${OUTPUT_CSV}"

# Rodada 1: Baseline Local Míope (Sem eBPF, processamento local com hashing míope em user space)
run_local_round 1 "Baseline_Local_MIOPE" "miope" "true"

# Rodada 2: eBPF Local Override Míope (Com eBPF bpf_override_return ativo no Kernel, processamento local)
run_local_round 2 "eBPF_Local_Override_MIOPE" "miope" "false"

# Rodada 3: Baseline Local Drain3 (Sem eBPF, processamento local com Drain3 regex em user space)
run_local_round 3 "Baseline_Local_Drain3" "drain3" "true"

echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}🎉  FIM DA BATERIA DE TESTES LOCAIS! RESULTADOS GRAVADOS EM:           ${NC}"
echo -e "    -> ${YELLOW}${OUTPUT_CSV}${NC}"
echo -e "${GREEN}======================================================================${NC}"
exit 0
