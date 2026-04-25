<div align="center">
    <img src="assets/logo.png" width="400" alt="Logscan-XDP Logo">
    <h1>🛡️ Logscan-XDP</h1>
    <i>High-Performance Security Logscanner powered by DBSCAN and C-eBPF.</i>
    <br>
    <b>Version: 1.0</b>
</div>

<br>

## 📌 Abstract


## 🎯 Key Features


---

## 🏛️ Architecture Blueprint

```mermaid
graph TD;
    classDef kernel fill:#f9d0c4,stroke:#333,stroke-width:2px;
    classDef user fill:#dae8fc,stroke:#333,stroke-width:2px;
    classDef external fill:#fff2cc,stroke:#333,stroke-width:2px;

    Attacker([Attacker Traffic / Script]) -->|Pacotes| NIC(Network Interface Card):::kernel

    subgraph Kernel Space [Espaço de Kernel - eBPF]
        NIC --> XDPProg{XDP Program}:::kernel
        XDPProg -->|Lookup do IP Malicioso| BPFMap[(eBPF Hash Map)]:::kernel
        XDPProg -- Se estiver no Mapa --> DropPacket((XDP_DROP <br/> Pacote Cai)):::kernel
        XDPProg -- Se limpo --> NetStack[Linux Network Stack]:::kernel
    end

    subgraph User Space [Espaço de Usuário]
        NetStack --> App[Application <br/> Apache / SSHD]:::user
        App -->|Escreve Textos| LogFile[(File: /var/log/*)]:::user
        LogFile -->|Real-time Tail| LogScan[Logscan Pipeline <br/> DBSCAN + TF-IDF]:::user
        LogScan -->|Avalia Clusters de Padrões| AnomalyDetect{Cluster <br/> é Anômalo?}:::user
        AnomalyDetect -- Sim --> ExtractIP[Extrai IP fonte <br/> do template]:::user
        ExtractIP -.-> |Atualiza as chaves <br/> via Syscall bpf| BPFMap
    end

    class Attacker,NIC,DropPacket external;
```

---

## 🛠️ Build & Usage


---

## ⚖️ License

Distributed under the **GNU General Public License v2.0**.
Designed for high-performance network analysis and community-driven security research.

