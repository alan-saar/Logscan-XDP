"""
Papel: O Orquestrador (Daemon do User Space).
O que faz: 
1. Compila e carrega o código C do eBPF (log_filter.c) no kernel do Linux usando a biblioteca BCC.
2. Inicia o DrainParser.
3. Fica ouvindo o PerfBuffer do kernel.
4. Quando um log novo chega, manda pro Parser e em seguida pro modelo (logdeep) avaliar.
"""

from bcc import BPF
import time

def main():
    print("Iniciando orquestrador Logscan com aceleração eBPF...")
    
    # Exemplo: bpf = BPF(src_file="ebpf/log_filter.c")
    # Exemplo: bpf.attach_kprobe(event="sys_write", fn_name="log_filter_kprobe")
    
    # Loop de escuta do PerfBuffer
    try:
        while True:
            time.sleep(1)
            # bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Saindo...")

if __name__ == "__main__":
    main()
