"""
@file bpf_updater.py
@brief Módulo de interação com o Data Plane (eBPF) via pylibbpf.

Este arquivo isola as chamadas para as syscalls bpf(), utilizando a
biblioteca pylibbpf para encontrar o mapa pinado no kernel e 
atualizar seu conteúdo com o IP convertido.
"""

import socket
import struct

# Como pylibbpf pode não estar instalado na máquina de teste ainda, 
# tratamos a importação para evitar quebra imediata do daemon.
try:
    import pylibbpf
    PYLIBBPF_AVAILABLE = True
except ImportError:
    PYLIBBPF_AVAILABLE = False
    print("[Aviso] pylibbpf não encontrado. Operando em modo de simulação.")

class BpfUpdater:
    """
    Classe para realizar o mapeamento do IP extraído e enviar para o kernel.
    """
    
    def __init__(self, map_name="malicious_ips"):
        """
        Inicializa o updater buscando a referência do mapa no kernel.
        
        :param map_name: Nome do mapa exportado pelo código XDP.
        """
        self.map_name = map_name
        self.map_fd = None
        
        if PYLIBBPF_AVAILABLE:
            # TODO: Obter o file descriptor do mapa BPF fixado no sysfs (ex: /sys/fs/bpf/malicious_ips)
            pass

    def _ip_to_network_bytes(self, ip_str: str) -> bytes:
        """
        Converte um IP em string para o formato Network Byte Order (__u32).
        
        Ex: '192.168.10.2' -> b'\xc0\xa8\n\x02'
        
        :param ip_str: IP em string.
        :return: Array de bytes.
        """
        # inet_aton já converte para network byte order
        return socket.inet_aton(ip_str)

    def block_ip(self, ip_str: str):
        """
        Atualiza o mapa eBPF para incluir o IP malicioso, sinalizando drop.
        
        :param ip_str: O endereço IP a ser bloqueado.
        """
        ip_bytes = self._ip_to_network_bytes(ip_str)
        # O XDP espera um valor __u64 (8 bytes). O formato "Q" empacota um unsigned long long nativo.
        value_bytes = struct.pack("Q", 1) 
        
        if PYLIBBPF_AVAILABLE and self.map_fd:
            print(f"[BPF] pylibbpf: Inserindo IP {ip_str} no mapa.")
            # pylibbpf.bpf_map_update_elem(self.map_fd, ip_bytes, value_bytes, pylibbpf.BPF_ANY)
        else:
            print(f"[BPF Mock] Simulação: IP {ip_str} (Bytes da chave: {ip_bytes.hex()}) bloqueado no mapa '{self.map_name}'.")
