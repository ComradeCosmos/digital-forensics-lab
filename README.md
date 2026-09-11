# 🛡️ Digital Forensics & Cyber Forensic Intelligence Laboratory

<p align="center">
  <img src="https://img.shields.io/badge/Maintained%20by-Subham%20Biswas-blue.svg?style=for-the-badge" alt="Maintained by Subham Biswas" />
  <img src="https://img.shields.io/badge/Mentor-Dr.%20Pooja%20Shah-purple.svg?style=for-the-badge" alt="Mentor Dr. Pooja Shah" />
  <img src="https://img.shields.io/badge/Environment-WSL%20Kali%20Linux%20%7C%20Docker-green.svg?style=for-the-badge" alt="WSL Kali & Docker" />
  <img src="https://img.shields.io/badge/Test%20Suite-100%25%20Verified-brightgreen.svg?style=for-the-badge" alt="Tests 100% Passed" />
  <img src="https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=for-the-badge" alt="Apache 2.0" />
</p>

---

## 📌 Overview

This repository provides a complete, modern, and containerized **Digital Forensics and Incident Response (DFIR)** laboratory ecosystem engineered and verified by **Subham Biswas** under the mentorship of **Dr. Pooja Shah**.

The platform encapsulates over **12,000 forensic evidence artifacts**, real-world enterprise disk images, network packet captures, mobile/IoT hardware chip-off extractions, and state-of-the-art **Artificial Intelligence (AI) forensic analysis pipelines**.

### 🌟 Key Highlights & Infrastructure Features
- 🐳 **Full Docker Containerization:** Turn-key [`Dockerfile`](Dockerfile) & [`docker-compose.yml`](docker-compose.yml) with pre-configured tools & web-based JupyterLab.
- 🐉 **Native WSL Kali Linux Support:** Pre-configured and verified on Kali Linux WSL with one-click launcher [`run_wsl_kali.bat`](run_wsl_kali.bat).
- 🧪 **Master Automated Test Suite:** Integrated verification runner [`run_all_labs.py`](run_all_labs.py) auditing datasets, XML event parsers, STIX threat graphs, and AI models.
- 📑 **Comprehensive Internship Documentation:** Official academic project report authored for Dr. Pooja Shah in [`INTERNSHIP_REPORT.md`](INTERNSHIP_REPORT.md).
- 📖 **Complete Lab Manual:** Technical handbook and execution cheat sheets in [`LAB_GUIDE.md`](LAB_GUIDE.md).

---

## 🚀 Quick Start Guide

### Option 1: Run via WSL Kali Linux (Recommended)
You can directly run all tools and scripts inside your native WSL Kali environment:

```bash
# Enter the lab workspace
cd /mnt/c/Users/alkes/.gemini/antigravity-ide/scratch/digital-forensics-lab

# Run the master automated test runner
python3 run_all_labs.py
```
*(On Windows, you can simply double-click [`run_wsl_kali.bat`](run_wsl_kali.bat) to launch the workspace terminal.)*

---

### Option 2: Run via Docker & JupyterLab
To build and start the containerized forensic workspace with interactive JupyterLab:

```bash
docker compose up -d --build
```
*(On Windows, double-click [`run_docker.bat`](run_docker.bat))*

- **JupyterLab Dashboard:** Open [http://localhost:8888/?token=forensics](http://localhost:8888/?token=forensics) in your web browser.
- **Interactive Container Shell:**
  ```bash
  docker exec -it digital_forensics_lab bash
  ```

---

## 🔬 Master Verification Suite (`run_all_labs.py`)

The repository includes an automated test harness validating the forensic modules:

```bash
python3 run_all_labs.py
```

### ✅ Automated Verification Output:
```text
=================================================================
      DIGITAL FORENSICS LAB - AUTOMATED MASTER RUNNER
=================================================================

[1] AI4Forensics: IP Identifier Evaluation
    - Confusion Matrix: [[33, 0], [1, 66]]
    - Accuracy: 99.00% | F1-Score: 0.9925  --> [SUCCESS]

[2] NIST Data Leakage: Security Event Log Forensics
    - Parsed: 1,193 XML security events (EventID 4608, 4624, etc.) --> [SUCCESS]

[3] Threat Intelligence: STIX 2.1 Evidence Graphs
    - Loaded: 12 cyber threat indicators (email, identity, relationship) --> [SUCCESS]

[4] Mobile & IoT Datasets Integrity Audit
    - Database: database.sqlite
    - Emails: 7,945 records | Persons: 513 records | Aliases: 850 records --> [SUCCESS]

[5] Linux Forensic CLI Tooling Verification
    - The Sleuth Kit (fls/mmls) : ver 4.14.0  [OK]
    - Steghide                  : ver 0.5.1   [OK]
    - Foremost                  : ver 1.5.7   [OK]
    - Hashdeep                  : ver 4.4     [OK]
    - SQLite3                   : ver 3.46.1  [OK]

=================================================================
  🎉 ALL FORENSIC LAB MODULES EXECUTED SUCCESSFULLY (100% PASS)
=================================================================
```

---

## 📚 Curriculum & Laboratory Modules

```
digital-forensics-lab/
├── 1. Host & Disk Forensics
│   ├── Basic_Computer_Skills_for_Forensics/   # Sleuth Kit, MMLS, FLS, ICAT, Data Carving
│   ├── NIST_Data_Leakage_Case/                # Enterprise Windows XP IP theft (14 Labs)
│   ├── P2P_Leakage/                           # Windows 10 BitTorrent, MFT & USN Timelines
│   └── Illegal_Possession_Images/             # File recovery, Steganography, Network extraction
│
├── 2. Network & Traffic Forensics
│   ├── Networking_Forensics/                  # TShark, Wireshark, SYN Flood, ARP & DNS Spoofing
│   └── Email_Harassment/                      # SMTP packet reconstruction & spoofed headers
│
├── 3. Mobile & IoT Hardware Forensics
│   ├── Android10/                             # Pixel 3 Android 10 (AOSP, GMS Maps, WhatsApp)
│   ├── iOS/                                   # iPhone iOS 13.4.1 (KnowledgeC, Health, Location)
│   ├── Echo_Device/                           # Amazon Echo Show 8 teardown & eMMC chip-off
│   ├── Eufy_Doorbell/                         # Smart Video Doorbell chip-off & P2P logs
│   └── Drone_DJI_Mavic_Air/                   # Flight telemetry & EXIF coordinate mapping
│
├── 4. AI & Threat Intelligence (AI4Forensics)
│   ├── AI4Forensics/                          # Suspect profiling with LLMs & STIX Graphing
│   ├── STIX_for_digital_forensics/            # STIX 2.1 Structured Threat Intelligence
│   └── Digital_Currency/ & Bitcoin/           # Cryptocurrency wallet & web activity artifacts
│
└── 5. Memory Forensics & Malware Analysis
    ├── Illegal_File_Transferring_Memory_Forensics/ # Volatility RAM dump extraction
    ├── NIST_Hacking_Case/                     # Historic intrusion investigations
    ├── Morris_Worm/                           # Historic UNIX worm artifact analysis
    └── Log4JShell/                            # Log4Shell exploit forensics
```

---

## 🛠️ Toolchain Matrix

| Category | Utilities / Libraries |
| :--- | :--- |
| **Filesystem & Disk Analysis** | The Sleuth Kit (`fls`, `icat`, `istat`, `mmls`, `fsstat`), `ewf-tools`, `pasco`, `hashdeep` |
| **Network & Packet Forensics** | `tshark`, `tcpdump`, Wireshark, Python `scapy`, `netfilterqueue` |
| **Artifact Parsers** | `evtx_dump.py`, `time_decode.py`, `prefetch.py`, `undark`, `liblnk-utils`, `libesedb-utils` |
| **Carving & Steganography** | `foremost`, `binwalk`, `steghide`, `stegdetect` |
| **Memory Forensics** | `volatility3`, `yara` |
| **AI, CTI & Data Science** | Python (`pandas`, `scikit-learn`, `stix2`, `openai`, `jupyterlab`) |

---

## 📑 Project Documents & Deliverables

- 📄 **[`INTERNSHIP_REPORT.md`](INTERNSHIP_REPORT.md):** Formal project report prepared by **Subham Biswas** for **Dr. Pooja Shah**.
- 📘 **[`LAB_GUIDE.md`](LAB_GUIDE.md):** Complete technical lab guide and execution operations manual.
- 🐳 **[`README_DOCKER.md`](README_DOCKER.md):** Containerized deployment and maintenance instructions.

---

## ⚖️ License & Attribution

- **Project Packaging & Engineering:** Maintained by **Subham Biswas** under the supervision of **Dr. Pooja Shah**.
- **Upstream Curriculum & Datasets:** Originates from coursework and grants supported by NSF, DOJ, and DHS (Frank W. Xu).
- **License:** Licensed under the **[Apache License 2.0](LICENSE)**.
