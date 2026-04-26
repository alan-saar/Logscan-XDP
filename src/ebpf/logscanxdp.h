/**
 * @file logscanxdp.h
 * @brief Cabeçalho principal para o programa eBPF Logscan-XDP.
 *
 * Este arquivo conterá as definições das estruturas de dados,
 * os mapas eBPF (BFP Maps) que serão compartilhados entre o
 * espaço de kernel (Data Plane) e o espaço de usuário (Control Plane),
 * bem como macros comuns utilizadas pelo programa XDP.
 */

#ifndef LOGSCANXDP_H
#define LOGSCANXDP_H

/**
 * @brief Mapa eBPF para armazenar IPs maliciosos.
 *
 * Tipo: Hash Map
 * Chave: Endereço IPv4 (__u32)
 * Valor: Contador de pacotes bloqueados (__u64)
 * Limite: 100.000 entradas
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u64);
} malicious_ips SEC(".maps");

#endif /* LOGSCANXDP_H */
