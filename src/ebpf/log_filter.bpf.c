/**
 * @file log_filter.bpf.c
 * @brief Filtro de Logs no Kernel com suporte a eBPF CO-RE (Compile Once - Run Everywhere).
 *
 * Intercepta a chamada de sistema (sys_write) antes dela gravar em disco.
 * Realiza o Hashing FNV-1a míope da mensagem de log, verifica a taxa de repetição
 * no eBPF Map, bloqueia hotspots redundantes com bpf_override_return e envia
 * logs novos ao User Space via Perf Buffer.
 *
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Definições de registradores para a arquitetura x86_64
#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#endif

// Estrutura de controle para taxa de repetição do hotspot
struct hotspot_val {
    __u64 count;            // Quantidade de ocorrências detectadas
    __u64 last_timestamp;   // Timestamp (em nanossegundos) da última atualização/reset
};

// Estrutura do evento de log enviado ao User Space
struct log_event_t {
    __u32 pid;              // PID do processo gerador do log
    char log_msg[64];     // Buffer de mensagem para análise do parser no user-space
};

// Mapa Hash de PIDs monitorados (Control Plane ativa dinamicamente)
// Chave: PID (__u32) | Valor: Ativo (__u8)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u8);
} pid_map SEC(".maps");

// Mapa Hash de controle de hotspots no Kernel
// Chave: ID do Hashing FNV-1a Míope (__u32) | Valor: Estrutura hotspot_val
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct hotspot_val);
} log_hotspots_map SEC(".maps");

// PerfBuffer de comunicação de alta performance Kernel -> User Space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} log_events SEC(".maps");

/**
 * @brief Algoritmo de Hashing Fowler-Noll-Vo (FNV-1a 32-bit) adaptado para Kernel.
 *        Ignora cabeçalhos de data/hora (primeiros 16 bytes) e caracteres numéricos.
 *
 * Parâmetros:
 * - buf: Ponteiro para o buffer local da mensagem lida do user-space.
 *
 * Retorno:
 * - hash: Assinatura estável (__u32) para clusterização do log.
 */
static inline __u32 calculate_fnv1a_miope(const char *buf) {
    __u32 hash = 2166136261U; // Offset Basis do FNV-1a 32-bit

    // Pulamos os primeiros 16 caracteres para ignorar timestamps (ex: "081109 203518 ")
    // e avaliamos os próximos 32 caracteres para extrair o padrão do log.
    #pragma unroll
    for (int i = 16; i < 48; i++) {
        char c = buf[i];

        // Terminação nula ou de linha interrompe o loop
        if (c == '\0' || c == '\n') {
            break;
        }

        // Salto "míope": ignoramos dígitos de 0 a 9 para neutralizar PIDs, blocos e IPs
        if (c >= '0' && c <= '9') {
            continue;
        }

        // Multiplicação FNV-1a pelo número primo
        hash = hash ^ (__u8)c;
        hash = hash * 16777619U;
    }
    return hash;
}

/**
 * @brief Kprobe acoplado na syscall sys_write.
 *        Intercepta as escritas de processos monitorados antes de irem a disco.
 */
SEC("kprobe/sys_write")
int log_filter_kprobe(struct pt_regs *ctx) {
    // 1. Obter o PID do processo atual
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 2. Verificar se o PID atual está no mapa de processos monitorados
    __u8 *monitored = bpf_map_lookup_elem(&pid_map, &pid);
    if (!monitored) {
        return 0; // Se não for da aplicação monitorada, sai instantaneamente (overhead zero)
    }

    // Extrai os parâmetros do contexto kprobe usando as macros de arquitetura
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    // 3. Ler o conteúdo do buffer (limitado pelo tamanho máximo do stack e verificado)
    char log_buf[64];

    // Inicialização explícita exigida pelo verificador eBPF
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        log_buf[i] = 0;
    }

    // Leitura segura do buffer do espaço de usuário para o kernel
    bpf_probe_read_user(&log_buf, sizeof(log_buf), (void *)buf);

    // 4. Calcular o Hashing Míope
    __u32 hash_id = calculate_fnv1a_miope(log_buf);

    // 5. Verificar taxa de recorrência (Rate Limiting de 100 logs/segundo)
    __u64 current_ns = bpf_ktime_get_ns();
    struct hotspot_val *val = bpf_map_lookup_elem(&log_hotspots_map, &hash_id);

    if (val) {
        __u64 elapsed = current_ns - val->last_timestamp;

        if (elapsed > 1000000000ULL) {
            // Mais de 1 segundo se passou, reseta a taxa limite
            val->count = 1;
            val->last_timestamp = current_ns;
        } else {
            // Dentro da janela de 1 segundo, incrementa contagem
            val->count += 1;

            if (val->count > 100) {
                // Limite estourado! É um Hotspot!
                // 6. bpf_override_return impede a escrita física, retornando sucesso (count) à aplicação
                bpf_override_return(ctx, count);
                return 0;
            }
        }
    } else {
        // Primeiro registro deste tipo de log, cria entrada no mapa
        struct hotspot_val new_val = {
            .count = 1,
            .last_timestamp = current_ns
        };
        bpf_map_update_elem(&log_hotspots_map, &hash_id, &new_val, BPF_ANY);
    }

    // Se não excedeu a taxa limite (log novo ou de baixa frequência):
    // 7. Envia uma cópia do evento para o User Space via PerfBuffer de alta performance
    struct log_event_t event = {};
    event.pid = pid;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        event.log_msg[i] = log_buf[i];
    }

    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// Licença obrigatória para carregamento no Kernel
char LICENSE[] SEC("license") = "GPL";
