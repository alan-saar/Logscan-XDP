#!/bin/bash
set -e
echo "[*] Debugging BPF load na máquina host..."
ulimit -l unlimited
sudo bpftool prog load src/ebpf/main.bpf.o /sys/fs/bpf/debug_logscan_prog
echo "[+] Sucesso! O objeto carregou via bpftool no host."
echo "[+] Atenção: o BPF foi deixado carregado em memória."
echo "[+] Para removê-lo posteriormente, execute: sudo rm /sys/fs/bpf/debug_logscan_prog"
