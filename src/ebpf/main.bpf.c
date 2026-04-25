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

/* A lógica do programa XDP (XDP_PROG) será implementada aqui */

/* Licença obrigatória para programas eBPF carregados no kernel */
char LICENSE[] SEC("license") = "GPL";
