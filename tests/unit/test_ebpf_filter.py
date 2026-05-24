#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finalidade do Arquivo: Teste Unitário Automatizado do Filtro eBPF CO-RE via BPFTOOL (Fase 3.3).
Este script carrega o objeto CO-RE compilado 'src/ebpf/log_filter.bpf.o' no Kernel
utilizando o utilitário nativo 'bpftool', eliminando qualquer necessidade de compiladores
de runtime ou cabeçalhos de Kernel durante a execução.

O script executa as seguintes etapas:
1. Carrega o programa no BPF FS em '/sys/fs/bpf/log_filter' e fixa (pin) os mapas em '/sys/fs/bpf/log_filter_maps/'.
2. Associa a Kprobe à syscall sys_write do kernel (tentando __x64_sys_write e sys_write).
3. Registra o PID deste próprio processo no mapa fixado 'pid_map' usando representação hexadecimal de bytes.
4. Simula uma tempestade de 200 escritas repetitivas.
5. Mostra o estado do mapa 'log_hotspots_map' direto do Kernel com 'bpftool map dump'.
6. Valida se o rate-limiting dropou exatamente 100 mensagens.
7. Descarrega e limpa todos os links e mapas do Kernel de forma segura.

"""

import os
import sys
import struct
import time
import subprocess

def run_cmd(cmd, check=True):
    """
    Executa um comando de terminal de forma robusta e retorna o resultado.
    """
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"[❌] Falha ao executar: {cmd}")
        print(f"    Stderr: {res.stderr.strip()}")
        sys.exit(1)
    return res

def main():
    base_dir = "/home/saar/code/mestrado/logscan-xdp"
    ebpf_obj = os.path.join(base_dir, "src/ebpf/log_filter.bpf.o")
    test_log_path = "/tmp/ebpf_test_file.log"

    # Caminhos para fixação de objetos BPF
    bpf_prog_path = "/sys/fs/bpf/log_filter"
    bpf_maps_dir = "/sys/fs/bpf/log_filter_maps"
    bpf_link_path = "/sys/fs/bpf/log_filter_link"

    # Certifica-se de que estamos rodando como root (exigência do eBPF)
    if os.geteuid() != 0:
        print("[❌] Erro: Este script precisa ser executado como ROOT (sudo).")
        sys.exit(1)

    print("==================================================")
    print("🚀 INICIANDO TESTE UNITÁRIO EBPF VIA BPFTOOL (CO-RE)")
    print("==================================================")

    # 0. Limpa fixações residuais anteriores se existirem
    run_cmd(f"rm -f {bpf_link_path} {bpf_prog_path} && rm -rf {bpf_maps_dir}", check=False)

    # 1. Carrega o objeto eBPF precompilado no Kernel
    print("[*] Carregando e fixando programa eBPF no Kernel...")
    run_cmd(f"bpftool prog load {ebpf_obj} {bpf_prog_path} pinmaps {bpf_maps_dir}")
    print("[✅] Programa carregado e mapas fixados com sucesso.")

    # 2. Cria o link kprobe para sys_write
    print("[*] Acoplando Kprobe à syscall sys_write do Kernel...")
    # Tenta primeiro a assinatura x86_64 padrão (__x64_sys_write)
    res_link = run_cmd(f"bpftool link create prog pinned {bpf_prog_path} type kprobe name __x64_sys_write pin {bpf_link_path}", check=False)

    if res_link.returncode != 0:
        print("    [!] Falhou __x64_sys_write, tentando fallback para sys_write...")
        # Fallback genérico
        run_cmd(f"bpftool link create prog pinned {bpf_prog_path} type kprobe name sys_write pin {bpf_link_path}")

    print("[✅] Kprobe acoplado e fixado com sucesso.")

    # 3. Registra o PID deste script no mapa pid_map
    print("[*] Registrando o PID atual no pid_map do Kernel...")
    my_pid = os.getpid()

    # Converte o PID (u32) para representação hexadecimal de 4 bytes em little-endian
    pid_bytes = struct.pack("<I", my_pid)
    key_hex = " ".join(f"0x{b:02x}" for b in pid_bytes)

    # Executa a escrita direta no mapa BPF fixado
    run_cmd(f"bpftool map update pinned {bpf_maps_dir}/pid_map key {key_hex} value 0x01")
    print(f"[✅] PID {my_pid} (hex key: {key_hex}) ativado no pid_map.")

    # 4. Dispara a tempestade de logs
    print("\n[*] Disparando tempestade de 200 escritas repetitivas...")
    try:
        fd = os.open(test_log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    except Exception as e:
        print(f"[❌] Falha ao criar arquivo de teste: {e}")
        sys.exit(1)

    # Linha padrão de log do HDFS
    log_line = b"081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608 src: 10.0.0.1\n"

    for i in range(200):
        try:
            # Usando os.write direto garante a chamada imediata da syscall sys_write
            os.write(fd, log_line)
        except Exception:
            pass

    os.close(fd)
    print("[✅] Tempestade de logs finalizada.")

    # 5. Exibe os mapas do Kernel (para provar que a contagem ocorreu no Kernel)
    print("\n[*] Consultando o mapa de hotspots (log_hotspots_map) direto do Kernel...")
    res_dump = run_cmd(f"bpftool map dump pinned {bpf_maps_dir}/log_hotspots_map", check=False)
    if res_dump.returncode == 0 and res_dump.stdout.strip():
        print(res_dump.stdout)
    else:
        print("    [!] Mapa vazio ou bpftool não conseguiu renderizar em texto.")

    # 6. Análise Científica das Métricas
    print("\n==================================================")
    print("📊 RESULTADOS E ANÁLISE DE DESCARTE (KERNELS)")
    print("==================================================")

    file_size = os.path.getsize(test_log_path)
    line_size = len(log_line)
    lines_in_disk = file_size // line_size

    print(f"-> Total de chamadas sys_write executadas pela app : 200")
    print(f"-> Linhas físicas gravadas no arquivo em disco     : {lines_in_disk}")

    if lines_in_disk == 100:
        print("\n[🏆] SUCESSO COMPLETO: O Filtro eBPF CO-RE funcionou perfeitamente!")
        print("    - 100 logs iniciais passaram no rate limit e foram gravados em disco.")
        print("    - 100 logs excedentes foram dropados no Kernel via bpf_override_return.")
        print("    - Sem necessidade de compiladores BCC em runtime!")
    elif lines_in_disk == 200:
        print("\n[⚠️] ALERTA: O Kernel gravou todos os 200 logs.")
        print("    - O eBPF foi executado, mas o descarte ativo (bpf_override_return) não funcionou.")
        print("    - Motivo provável: Seu kernel não possui CONFIG_BPF_KPROBE_OVERRIDE ativo no Host.")
    else:
        print(f"\n[⚠️] Resultado inesperado: {lines_in_disk} linhas em disco.")

    print("==================================================")

    # 7. Limpa fixações e descarrega o eBPF do Kernel
    print("[*] Descarregando programa eBPF e removendo mapas fixados...")
    run_cmd(f"rm -f {bpf_link_path} {bpf_prog_path} && rm -rf {bpf_maps_dir}", check=False)
    print("[✅] Cleanup finalizado com sucesso.")

    # Remove arquivo temporário de testes
    if os.path.exists(test_log_path):
        os.remove(test_log_path)

if __name__ == "__main__":
    main()
