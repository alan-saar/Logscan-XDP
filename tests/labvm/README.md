# Roteiro de Laboratório: Avaliação de Rede UDP e Aceleração eBPF em VMs

Este diretório contém a suíte de testes projetada para isolar a variável de rede UDP, quantificar perdas físicas de pacotes e comparar o desempenho do processamento de logs com e sem a aceleração eBPF no Kernel.

O laboratório utiliza duas Máquinas Virtuais (VMs) com a instalação limpa do **Ubuntu Server 24.04**:
*   **VM Vítima (Receptor & IA)**: `192.168.122.100` (Porta UDP padrão: `9999`)
*   **VM Atacante (Emissor de Tráfego)**: `192.168.122.101`

---

## 1. Como a Perda de Pacotes UDP é Medida (e por que não usamos o iperf)

Para este experimento, **não utilizamos o iperf** para o controle e medição de perda. O iperf é uma ferramenta de benchmark de rede sintética que mede a largura de banda máxima disponível. Para o nosso artigo científico, o objetivo é quantificar a perda de pacotes **causada pela sobrecarga de processamento da IA** em espaço de usuário sob uma carga de logs reais, isolando o impacto do parser (Míope vs Drain3) e o ganho do filtro eBPF no Kernel.

A perda é quantificada de duas formas complementares e precisas:

1.  **Perda Aplicacional (Logs de Fato Processados)**:
    Calculada subtraindo a quantidade de logs gravados em disco na VM Vítima do total de logs enviados em memória pela VM Atacante (exatamente 42.229 logs do dataset `HDFS_test.log`).
    $$\text{Perda Aplicacional (\%)} = \frac{\text{Logs Enviados} - \text{Logs Recebidos}}{\text{Logs Enviados}} \times 100$$

2.  **Perda Interna do Kernel (Saturação de Buffer do Socket)**:
    Quando a aplicação em User Space (IA LSTM) é mais lenta do que a taxa de pacotes UDP chegando pela rede, a fila de recepção do socket no Kernel Linux atinge o limite e transborda. O Kernel então descarta os pacotes excedentes.
    Monitoramos esses descartes consultando as estatísticas SNMP nativas do Kernel no arquivo `/proc/net/snmp` (especificamente as métricas `RcvbufErrors` e `InErrors` da seção `Udp:`) imediatamente antes e depois de cada rodada de teste.

---

## 2. Preparação das VMs (Instalação Limpa Ubuntu Server 24.04)

Siga os passos abaixo em cada VM para preparar o ambiente de laboratório.

### 2.1. Configurações em Ambas as VMs (Vítima e Atacante)

1.  **Atualizar o sistema**:
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

2.  **Instalar dependências de compilação e rede**:
    ```bash
    sudo apt install -y build-essential git python3-pip python3-venv \
                       clang llvm libelf-dev libpcap-dev pkg-config \
                       libbpf-dev gcc-multilib
    ```

3.  **Ajustar buffers de socket UDP no Kernel Linux (Crucial)**:
    Por padrão, o Ubuntu limita os buffers do socket UDP a valores baixos (geralmente 208 KB), o que causaria descartes mesmo em taxas baixas. Aumentamos o limite máximo para 16 MB para garantir que os drops ocorram por causa do tempo de inferência da IA e não por má configuração de rede local:
    ```bash
    # Aplicar em tempo de execução
    sudo sysctl -w net.core.rmem_max=16777216
    sudo sysctl -w net.core.wmem_max=16777216
    sudo sysctl -w net.core.rmem_default=4194304
    sudo sysctl -w net.core.wmem_default=4194304
    ```
    *(Para tornar persistente após o reboot, adicione essas linhas ao final de `/etc/sysctl.conf`).*

---

### 2.2. Configuração Específica da VM Vítima (`192.168.122.100`)

A VM Vítima rodará a inferência de IA e o receptor com suporte a eBPF. 

1.  **Clonar o repositório ou copiar a pasta do projeto**:
    ```bash
    git clone https://github.com/alan-saar/Logscan-XDP.git /home/saar/code/mestrado/logscan-xdp
    cd /home/saar/code/mestrado/logscan-xdp
    git checkout feature/xdp-preprocessing
    ```

2.  **Criar e configurar o Ambiente Virtual do Python**:
    ```bash
    python3 -m venv .venv-logscan
    source .venv-logscan/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install psutil
    ```

3.  **Instalar e Configurar o `bpftool`**:
    O `bpftool` é utilizado para carregar o programa eBPF no Kernel e gerenciar os mapas. Instale-o a partir dos repositórios oficiais ou compile-o:
    ```bash
    sudo apt install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)
    sudo apt install -y libbpf-dev gcc-multilib
    ```
    Verifique o funcionamento com `bpftool --version`.

4.  **Compilar o Programa eBPF**:
    Navegue até a pasta de código eBPF e compile o filtro CO-RE:
    ```bash
    cd /home/saar/code/mestrado/logscan-xdp
    make clean && make
    ```
    Isso deve gerar o binário ELF eBPF compilado em `/home/saar/code/mestrado/logscan-xdp/src/ebpf/log_filter.bpf.o`.

5.  **Verificar arquivos obrigatórios para a IA**:
    Certifique-se de que os seguintes arquivos existem no diretório antes de rodar os testes:
    *   Modelo treinado PyTorch: `/home/saar/code/mestrado/logscan-xdp/src/logdeep/result/deeplog/deeplog_last.pth`
    *   Tabela de rótulos de teste: `/home/saar/code/mestrado/logscan-xdp/full_dataset/HDFS/HDFS_test_labels.json`
    *   Tabela de hashes Míope: `/home/saar/code/mestrado/logscan-xdp/full_dataset/HDFS/hash_to_event.json`
    *   Templates do Drain3: `/home/saar/code/mestrado/logscan-xdp/full_dataset/HDFS/HDFS_full.log_templates.csv`

---

### 2.3. Configuração Específica da VM Atacante (`192.168.122.101`)

A VM Atacante precisa apenas do script transmissor (`sender_vm.py`) e do dataset em texto plano para transmissão via rede UDP.

1.  **Copiar o script transmissor e o arquivo de logs**:
    Crie um diretório de trabalho na VM Atacante e copie o arquivo [sender_vm.py](file:///home/saar/code/mestrado/logscan-xdp/tests/labvm/sender_vm.py) e o arquivo de log original `HDFS_test.log` (que contém os 42.229 logs de teste) para a mesma pasta.

2.  **Verificar ambiente Python**:
    O script de envio de logs não possui dependências pesadas, necessitando apenas do Python 3 padrão.

---

## 3. Guia de Execução das Rodadas de Teste

Para facilitar o experimento científico e consolidar os dados, criamos o script interativo `run_experiments.sh` na VM Vítima. Ele guiará o usuário pelas 7 rodadas de testes passo a passo.

### Passo 1: Iniciar o Script na VM Vítima
Na VM Vítima, execute o script de automação dentro do ambiente virtual:
```bash
cd /home/saar/code/mestrado/logscan-xdp/tests/labvm
source ../../.venv-logscan/activate
./run_experiments.sh
```

### Passo 2: Acompanhar e Executar os comandos correspondentes na VM Atacante
O script na VM Vítima irá aguardar o sinal e exibirá exatamente qual comando você deve rodar no terminal da VM Atacante.

Aqui está o resumo das rodadas automatizadas pelo script:

| Rodada | Cenário | Parser | eBPF no Kernel | Taxa no Atacante | Comando a Executar no Atacante |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `Baseline_UDP_Flood` | Míope | DESATIVADO | Flood (Taxa máxima) | `python3 sender_vm.py --ip 192.168.122.100 --rate 0` |
| **2** | `Baseline_UDP_Control_1000` | Míope | DESATIVADO | 1000 logs/s | `python3 sender_vm.py --ip 192.168.122.100 --rate 1000` |
| **3** | `Baseline_UDP_Control_100` | Míope | DESATIVADO | 100 logs/s | `python3 sender_vm.py --ip 192.168.122.100 --rate 100` |
| **4** | `Drain3_UDP_Flood` | Drain3 | DESATIVADO | Flood (Taxa máxima) | `python3 sender_vm.py --ip 192.168.122.100 --rate 0` |
| **5** | `Drain3_UDP_Control_500` | Drain3 | DESATIVADO | 500 logs/s | `python3 sender_vm.py --ip 192.168.122.100 --rate 500` |
| **6** | `MIOPE_eBPF_Flood` | Míope | **ATIVADO** | Flood (Taxa máxima) | `python3 sender_vm.py --ip 192.168.122.100 --rate 0` |
| **7** | `MIOPE_eBPF_Control_1000` | Míope | **ATIVADO** | 1000 logs/s | `python3 sender_vm.py --ip 192.168.122.100 --rate 1000` |

### Fluxo de Cada Rodada:
1.  O script na VM Vítima exibe o nome da rodada e as instruções.
2.  Você pressiona `ENTER` na VM Vítima. O receptor do Python inicializa a escuta do socket UDP e aguarda o tráfego.
3.  Você executa o respectivo comando `python3 sender_vm.py ...` na VM Atacante.
4.  O Atacante envia todas as linhas do HDFS e exibe o tempo total gasto e a taxa alcançada.
5.  O Receptor na VM Vítima processa os logs. Quando a rede cessa por mais de 5 segundos, o receptor fecha o socket, calcula as perdas aplicacionais, extrai as métricas SNMP de buffers cheios do Kernel Linux e anexa os dados no arquivo `results_vm.csv`.
6.  O script avança para a próxima rodada.

---

## 4. Estrutura dos Resultados Gerados

Após a conclusão das 7 rodadas, os resultados estarão gravados no arquivo:
`tests/labvm/results_vm.csv`

Ele conterá as seguintes colunas para cada cenário testado:
*   `Scenario`: Nome da rodada executada.
*   `Parser`: O algoritmo de parsing utilizado (`miope` ou `drain3`).
*   `LogsSent`: Total de logs enviados pelo transmissor (sempre 42229).
*   `LogsReceived`: Total de logs gravados e analisados pela IA na vítima.
*   `AppLossPercent`: Porcentagem de perda de logs aplicacional.
*   `KernelBufDrops`: Quantidade absoluta de drops de buffer do socket UDP contabilizada pelo Kernel Linux (`RcvbufErrors` no SNMP).
*   `KernelUdpErrors`: Erros de recepção de entrada UDP contabilizados pelo Kernel (`InErrors` no SNMP).
*   `Precision` / `Recall` / `F1_Score`: Métricas de acurácia da IA obtidas para cada cenário (para avaliar se a perda de pacotes degradou a detecção de anomalias).
*   `DurationSeconds`: Tempo total que a IA levou processando os logs.
*   `MaxCPU` / `MaxRAM`: Pico de consumo de recursos de CPU e RAM de hardware.

Esses dados podem ser copiados de volta para a sua máquina host para gerar gráficos comparativos idênticos aos exibidos nos resultados de laboratório.
