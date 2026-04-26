/**
 * @file main.bpf.c
 * @brief Programa principal eBPF/XDP para mitigação dinâmica de ameaças.
 *
 * Este arquivo contém a lógica XDP que será anexada à interface de rede.
 * Ele é responsável por inspecionar os pacotes recebidos, extrair o IP
 * de origem e realizar uma busca (lookup) em um mapa eBPF gerenciado
 * pelo daemon Logscan no user-space. Dependendo do resultado, decide
 * por descartar (XDP_DROP) ou permitir a passagem (XDP_PASS) do pacote.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "logscanxdp.h"

/* Definindo a constante do protocolo IPv4 caso não definida */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/**
 * @brief Função principal do XDP para filtrar pacotes.
 *
 * @param ctx Contexto XDP com dados do pacote interceptado.
 * @return XDP_DROP se o IP constar no mapa malicioso, senão XDP_PASS.
 */
SEC("xdp")
int xdp_drop_malicious(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    /* Verifica os limites do cabeçalho Ethernet */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Apenas prossegue se for tráfego IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    /* Verifica os limites do cabeçalho IPv4 */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Extrai o IP de origem (saddr já está no formato network byte order) */
    __u32 src_ip = ip->saddr;

    /* Busca o IP no mapa de anomalias (Logscan fará o update deste mapa do outro lado) */
    __u64 *value = bpf_map_lookup_elem(&malicious_ips, &src_ip);
    if (value) {
        /* Incrementa o número de tentativas bloqueadas para este IP */
        __sync_fetch_and_add(value, 1);
        bpf_printk("Logscan-XDP: IP bloqueado detectado. Dropando pacote.\n");
        return XDP_DROP;
    }

    /* Caso contrário, pacote é benigno */
    return XDP_PASS;
}

/* Licença obrigatória para programas eBPF carregados no kernel */
char LICENSE[] SEC("license") = "GPL";
