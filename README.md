<div align="center">
    <img src="assets/logo.png" width="400" alt="Logscan-XDP Logo">
    <h1>🛡️ Logscan-XDP</h1>
    <i>Dynamic Threat Mitigation in the Kernel based on Automatic Log Clustering powered by DBSCAN and C-eBPF</i>
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

    Attacker([Attacker Traffic / Script]) -->|Packets| NIC(Network Interface Card):::kernel

    subgraph Kernel Space [Kernel Space - eBPF]
        NIC --> XDPProg{XDP Program}:::kernel
        XDPProg -->|Lookup Malicious IP | BPFMap[(eBPF Hash Map)]:::kernel
        XDPProg -- If in the Map --> DropPacket((XDP_DROP <br/>)):::kernel
        XDPProg -- If clean --> NetStack[Linux Network Stack]:::kernel
    end

    subgraph User Space [User Space]
        NetStack --> App[Application <br/> Apache / SSHD]:::user
        App -->|Writes Logfile| LogFile[(File: /var/log/*)]:::user
        LogFile -->|Real-time Tail| LogScan[Logscan Pipeline <br/> DBSCAN + TF-IDF]:::user
        LogScan -->|Evaluate Pattern Clusters| AnomalyDetect{Cluster <br/> is Anomalous?}:::user
        AnomalyDetect -- Yes --> ExtractIP[Extract source IP <br/> from template]:::user
        ExtractIP -.-> |Update the keys <br/> via bpf syscalls| BPFMap
    end

    class Attacker,NIC,DropPacket external;
```

---

## 🛠️ Build & Usage


---

## ⚖️ License

Distributed under the **GNU General Public License v2.0**.
Designed for high-performance network analysis and community-driven security research.

