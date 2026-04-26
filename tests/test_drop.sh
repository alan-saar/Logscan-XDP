#!/bin/bash
set -e

echo "========================================"
echo "[1/4] Compilando código XDP..."
echo "========================================"
make

echo ""
echo "========================================"
echo "[2/4] Deploy da Topologia de Teste..."
echo "========================================"
sudo containerlab deploy --reconfigure -t tests/containerlab/topology.clab.yml
sleep 2

echo ""
echo "========================================"
echo "[3/4] Anexando programa XDP e Testando PING..."
echo "========================================"
# Preparando o container: instalando bpftool (pois o iproute2 do alpine rejeita a alocação de memória BPF via ip link)
docker exec clab-logscan-server apk add bpftool --no-cache >/dev/null 2>&1

# Copiando o arquivo compilado para dentro do container do servidor
docker cp src/ebpf/main.bpf.o clab-logscan-server:/tmp/main.bpf.o

# Carregando o programa BPF usando ulimit e anexando com bpftool net attach (usa ulimit porque o container não carrega o mapa com tamanho de 100 mil)
docker exec clab-logscan-server bash -c 'ulimit -l unlimited && bpftool prog load /tmp/main.bpf.o /sys/fs/bpf/xdp_prog'
PROG_ID=$(docker exec clab-logscan-server bpftool prog show name xdp_drop_malicious | grep -o -E '^[0-9]+' | head -n1)
docker exec clab-logscan-server bpftool net attach xdpgeneric id $PROG_ID dev eth1

echo "[*] Testando PING antes do bloqueio (deve funcionar e retornar 0 pacotes perdidos)..."
docker exec clab-logscan-attacker ping -c 2 192.168.10.3

echo ""
echo "========================================"
echo "[4/4] Injetando regra de bloqueio no mapa eBPF..."
echo "========================================"
# IP 192.168.10.2 em Hex: C0 A8 0A 02
docker exec clab-logscan-server bash -c '
MAP_ID=$(bpftool map list | grep malicious_ips | cut -d":" -f1)
bpftool map update id $MAP_ID key hex c0 a8 0a 02 value hex 01 00 00 00 00 00 00 00
'

echo "[*] Testando PING após bloqueio (deve falhar com 100% packet loss)..."
set +e # O comando ping deve falhar
docker exec clab-logscan-attacker ping -c 2 -W 1 192.168.10.3
PING_RET=$?
set -e

if [ $PING_RET -ne 0 ]; then
    echo "[!] PING BLOQUEADO COM SUCESSO PELO XDP!"
else
    echo "[X] FALHA: O PING AINDA ESTA FUNCIONANDO!"
    exit 1
fi


echo ""
echo "========================================"
echo "[*] Limpeza: Destruindo Topologia..."
echo "========================================"
sudo containerlab destroy -t tests/containerlab/topology.clab.yml
