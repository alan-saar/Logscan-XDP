#!/usr/bin/env python3
"""
@file test_local_bpftool.py
@brief Script para testar a injeção nativa via bpftool na máquina hospedeira.

Este script tem como objetivo validar o comportamento do `BpfUpdater`
no modo "Host Nativo" (sem informar um container). Ele instancia o
updater e aciona a injeção de uma regra de drop contra o IP 2.2.2.2
usando chamadas ao `bpftool` via subprocess.
Assume-se que o mapa `malicious_ips` já esteja carregado no kernel do host
pelo script `debug_load.sh`.
"""

import sys
import os
import subprocess
import struct
import socket

# Adiciona o diretório raiz ao path para importar o bpf_updater
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src', 'logscan'))

from bpf_updater import BpfUpdater

def test_local_bpftool():
    print("=============================================")
    print("Testando Atualização via Bpftool no Host Local")
    print("=============================================")
    
    print("[*] Iniciando BpfUpdater nativo...")
    try:
        # Modo host: container_name=None
        updater = BpfUpdater(map_name="malicious_ips")
        
        # O debug_load.sh já deve ter subido isso, então bpftool map list deve mostrar
        print("[*] Tentando bloquear IP de teste '2.2.2.2'...")
        updater.block_ip("2.2.2.2")
        
        # Testando busca no mapa para validar a inserção!
        print("[*] Lendo mapa diretamente pelo shell para confirmar a injeção...")
        
        cmd_get_id = "sudo bpftool map list | grep malicious_ips | cut -d':' -f1"
        map_id_str = subprocess.check_output(cmd_get_id, shell=True, text=True).strip()
        
        if not map_id_str:
            print("[X] Falha: Mapa não encontrado para validação.")
            sys.exit(1)
            
        # Pede para o bpftool despejar em formato JSON para podermos formatar facilmente
        cmd_dump = f"sudo bpftool map dump id {map_id_str} -j"
        dump_output = subprocess.check_output(cmd_dump, shell=True, text=True)
        
        import json
        try:
            dump_data = json.loads(dump_output)
            encontrado = False
            print("\n[+] Mostrando conteúdo lido da memória com a 'Mágica' do Python:")
            
            for item in dump_data:
                key_raw = item.get("key")
                
                # Bpftool pode retornar inteiros puros, strings hexadecimais, 
                # ou listas de bytes (ex: ["02", "02", "02", "02"]) dependendo do BTF/Versão!
                if isinstance(key_raw, list):
                    # Garante que cada item da lista vire um int antes de converter pra bytes
                    parsed_bytes = [int(x, 16) if isinstance(x, str) else int(x) for x in key_raw]
                    ip_bytes_read = bytes(parsed_bytes)
                else:
                    if isinstance(key_raw, str):
                        key_int = int(key_raw, 16) if key_raw.startswith("0x") else int(key_raw)
                    else:
                        key_int = int(key_raw)
                    
                    # Converte o Inteiro (ex: 33686018) de volta para Bytes
                    ip_bytes_read = struct.pack("I", key_int)
                ip_string = socket.inet_ntoa(ip_bytes_read)
                
                value_raw = item.get("value")
                if isinstance(value_raw, list):
                    # Garante que cada item da lista vire um int antes de converter pra bytes
                    parsed_val_bytes = [int(x, 16) if isinstance(x, str) else int(x) for x in value_raw]
                    value_int = struct.unpack("Q", bytes(parsed_val_bytes))[0]
                else:
                    value_int = int(value_raw)

                print(f"    -> Atacante Encontrado: {ip_string} (Bloqueios: {value_int})")
                
                if ip_string == "2.2.2.2":
                    encontrado = True
                    
            if encontrado:
                print("\n[✅] SUCESSO! O IP 2.2.2.2 foi lido de volta do kernel e formatado corretamente!")
            else:
                print("\n[X] FALHA: A chave não foi encontrada no dump do mapa.")
                sys.exit(1)
        except json.JSONDecodeError:
            print("[X] Erro ao interpretar a saída JSON do bpftool.")
            sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(f"\n[X] Exceção Capturada ao chamar bpftool: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[X] Exceção Capturada: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_local_bpftool()
