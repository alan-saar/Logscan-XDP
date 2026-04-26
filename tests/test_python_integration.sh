#!/bin/bash
set -e

echo "========================================"
echo "[1/5] Compilando código XDP..."
echo "========================================"
make

echo ""
echo "========================================"
echo "[2/5] Deploy da Topologia de Teste..."
echo "========================================"
sudo containerlab deploy --reconfigure -t tests/containerlab/topology.clab.yml
sleep 2

echo ""
echo "========================================"
echo "[3/5] Anexando programa XDP..."
echo "========================================"
# Preparando o container e instalando bpftool
docker exec clab-logscan-server apk add bpftool --no-cache >/dev/null 2>&1

# Copiando o arquivo compilado para dentro do container do servidor
docker cp src/ebpf/main.bpf.o clab-logscan-server:/tmp/main.bpf.o

# Carregando o programa BPF e anexando
docker exec clab-logscan-server bash -c 'ulimit -l unlimited && bpftool prog load /tmp/main.bpf.o /sys/fs/bpf/xdp_prog'
PROG_ID=$(docker exec clab-logscan-server bpftool prog show name xdp_drop_malicious | grep -o -E '^[0-9]+' | head -n1)
docker exec clab-logscan-server bpftool net attach xdpgeneric id $PROG_ID dev eth1

echo "[*] Testando PING antes do bloqueio (deve funcionar e retornar 0 pacotes perdidos)..."
docker exec clab-logscan-attacker ping -c 2 192.168.10.3

echo ""
echo "========================================"
echo "[4/5] Iniciando Daemon Python (Control Plane) e Injetando Log..."
echo "========================================"
# Cria um log falso
DUMMY_LOG="/tmp/dummy_auth.log"
touch $DUMMY_LOG

# Inicia o daemon python em background
echo "[*] Iniciando src/logscan/main.py (Micro-batching de 1s)..."
.venv/bin/python src/logscan/main.py -l $DUMMY_LOG -c clab-logscan-server -w 1 &
DAEMON_PID=$!
sleep 2

# Simula uma anomalia vinda do Attacker (192.168.10.2)
echo "[*] Escrevendo linha de anomalia no log..."
echo "May 20 12:00:00 server sshd[1234]: Failed password for invalid user root from 192.168.10.2 port 40562 ssh2" >> $DUMMY_LOG
sleep 3

echo ""
echo "========================================"
echo "[5/5] Testando PING após bloqueio dinâmico (deve falhar!)..."
echo "========================================"
set +e
docker exec clab-logscan-attacker ping -c 2 -W 1 192.168.10.3
PING_RET=$?
set -e

# Mata o daemon
kill $DAEMON_PID

if [ $PING_RET -ne 0 ]; then
    echo "[!] PING BLOQUEADO COM SUCESSO! INTEGRAÇÃO PYTHON -> eBPF FUNCIONANDO!"
else
    echo "[X] FALHA: O PING AINDA ESTA FUNCIONANDO!"
    exit 1
fi

echo ""
echo "========================================"
echo "[*] Limpeza: Destruindo Topologia..."
echo "========================================"
sudo containerlab destroy -t tests/containerlab/topology.clab.yml
rm -f $DUMMY_LOG
