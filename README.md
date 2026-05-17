<div align="center">
    <img src="assets/logo.png" width="400" alt="Logscan-XDP Logo">
    <h1>🛡️ Logscan-XDP</h1>
    <i>Accelerating Deep Learning Log Anomaly Detection (DeepLog) using eBPF/XDP In-Kernel Pre-processing</i>
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

    LogSource([System/App Logs]) -->|Events| Syscalls:::kernel

    subgraph Kernel Space [Kernel Space - eBPF]
        Syscalls --> eBPFProg{eBPF Kprobes/XDP}:::kernel
        eBPFProg -->|Identify Hotspots / Normal Patterns| BPFMap[(eBPF Hash Map)]:::kernel
        eBPFProg -- Filtered / Aggregated Logs --> PerfBuffer[eBPF Ring/Perf Buffer]:::kernel
    end

    subgraph User Space [User Space]
        PerfBuffer --> LogParser[Log Parser / Drain]:::user
        LogParser --> DeepLog[DeepLog / LogAnomaly <br/> PyTorch Model]:::user
        DeepLog -->|Predict| AnomalyDetect{Anomaly Detected?}:::user
        AnomalyDetect -- Yes --> Alert((Alert / Mitigation)):::user
    end

    class LogSource,Alert external;
```

---

## 📁 Project Structure

- `assets/`: Static assets such as logos and images.
- `src/`: Source code directory for the project.
  - `ebpf/`: eBPF/XDP C programs for log filtering and high-performance pre-processing in the kernel.
  - `logdeep/`: Submodule containing PyTorch implementations of deep learning-based log anomaly detection models (DeepLog).

---

## 🛠️ Build & Usage

**Build:**
```bash
# Build instructions to be defined
```

**Usage:**
```bash
# Usage instructions to be defined
```

---

## 🧪 Tests

**Run tests:**
```bash
# Test instructions to be defined
```

---

## ⚖️ License

Distributed under the **GNU General Public License v2.0**.
Designed for high-performance network analysis and community-driven security research.

