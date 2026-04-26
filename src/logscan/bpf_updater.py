"""
@file bpf_updater.py
@brief Módulo de interação com o Data Plane (eBPF) via bpftool.

Este arquivo isola as chamadas para atualização dos mapas eBPF. Ele atua
como uma ponte agnóstica de ambiente, disparando as atualizações através da
ferramenta CLI `bpftool`. Se acionado em modo de container (testes), 
orquestrará comandos Docker; caso contrário, executará nativamente no Host.
"""

import socket
import struct
import subprocess

class BpfUpdater:
    """
    Classe para realizar o mapeamento do IP extraído e atualizar o mapa BPF 
    diretamente via comando CLI bpftool.
    """
    
    def __init__(self, map_name="malicious_ips", container_name=None):
        """
        Inicializa o updater com o nome do mapa alvo.
        
        :param map_name: Nome do mapa exportado pelo código XDP.
        :param container_name: Se fornecido, usa docker exec para atualizar o mapa no container de testes.
        """
        self.map_name = map_name
        self.container_name = container_name

    def _ip_to_network_bytes(self, ip_str: str) -> bytes:
        """
        Converte um IP em string para o formato Network Byte Order (__u32).
        Ex: '192.168.10.2' -> b'\xc0\xa8\n\x02'
        
        :param ip_str: O endereço IP em formato de texto.
        :return: A representação binária do IP.
        """
        return socket.inet_aton(ip_str)

    def _update_map(self, ip_bytes: bytes, value_bytes: bytes):
        """
        Atualiza o mapa via `bpftool` (localmente ou via docker exec).
        
        :param ip_bytes: Chave formatada em binário (IP).
        :param value_bytes: Valor formatado em binário (Contador/Flag).
        """
        # Converte bytes para representação hex que o bpftool espera, ex: "c0 a8 0a 02"
        key_hex = " ".join([f"{b:02x}" for b in ip_bytes])
        val_hex = " ".join([f"{b:02x}" for b in value_bytes])
        
        prefix = f"docker exec {self.container_name} " if self.container_name else "sudo "
        ambiente = f"no container {self.container_name}" if self.container_name else "no host local"
        
        print(f"[BPF Updater] Injetando regra {ambiente} via bpftool...")
        
        # Obtém o ID do mapa dinamicamente
        cmd_get_id = f"{prefix}bpftool map list | grep {self.map_name} | cut -d':' -f1"
        try:
            map_id_str = subprocess.check_output(cmd_get_id, shell=True, text=True).strip()
            if not map_id_str:
                print(f"[!] Erro: Mapa {self.map_name} não encontrado {ambiente}.")
                return
            
            # Atualiza o mapa injetando os bytes formatados em hex
            cmd_update = f"{prefix}bpftool map update id {map_id_str} key hex {key_hex} value hex {val_hex}"
            subprocess.check_call(cmd_update, shell=True)
            print(f"[+] Regra injetada com sucesso no BPF map (ID: {map_id_str})!")
        except subprocess.CalledProcessError as e:
            print(f"[!] Falha ao executar bpftool {ambiente}: {e}")

    def block_ip(self, ip_str: str):
        """
        Atualiza o mapa eBPF para incluir o IP malicioso, sinalizando drop imediato
        pelo programa XDP (Data Plane).
        
        :param ip_str: Endereço IP do atacante.
        """
        ip_bytes = self._ip_to_network_bytes(ip_str)
        # O XDP espera um valor __u64 (8 bytes). 
        # O formato "Q" no struct empacota um unsigned long long nativo.
        value_bytes = struct.pack("Q", 1) 
        
        self._update_map(ip_bytes, value_bytes)
