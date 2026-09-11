# Internship Project Report: Digital Forensics Lab Environment Engineering & Automated Verification

**Intern Name:** Subham Biswas  
**Faculty Supervisor / Mentor:** Dr. Pooja Shah  
**Project Domain:** Digital Forensics, Cyber Threat Intelligence & Forensic Toolchain Engineering  
**Date:** September 2026  

---

## 1. Executive Summary

This report documents the research, toolchain infrastructure engineering, and automated verification conducted during the digital forensics internship under the guidance of **Dr. Pooja Shah**.

The primary objective of this project was to analyze, containerize, and systematically validate a comprehensive **Digital Forensics and Incident Response (DFIR)** laboratory ecosystem consisting of over **12,000 evidence artifacts**, real-world host/network case studies, mobile/IoT hardware chip-off extractions, and state-of-the-art **Artificial Intelligence (AI) forensic modules**.

Key contributions achieved during this internship include:
1. **Curriculum & Dataset Architecture Analysis:** In-depth technical review of 22 forensic modules covering disk, network, memory, IoT, and AI investigations.
2. **Cross-Platform Containerization (Docker):** Creation of a unified Dockerfile and Docker Compose deployment stack encapsulating both legacy and modern forensic utilities alongside JupyterLab.
3. **WSL Kali Linux Environment Deployment:** Configuration and testing of native Linux forensic toolchains (The Sleuth Kit, Foremost, Binwalk, Steghide, Hashdeep) on Windows Subsystem for Linux.
4. **Master Automated Validation Suite (`run_all_labs.py`):** Development and execution of an end-to-end test runner validating AI classification accuracy, XML event log parsing, STIX 2.1 threat intelligence graph generation, and SQLite database integrity with 100% test pass rates.

---

## 2. Project Objectives

- **Infrastructure Modernization:** Eliminate dependency conflicts and manual installation bottlenecks by building a turn-key containerized execution environment.
- **Empirical Validation of AI in Forensics:** Verify LLM fine-tuning techniques applied to unstructured forensic SQLite logs for automated indicator extraction.
- **Case Study Analysis:** Audit evidence from real-world datasets including NIST data leakage, P2P BitTorrent file exfiltration, Android/iOS databases, and IoT eMMC chip-off dumps.
- **Technical Documentation:** Author standardized lab guides and execution workflows for academic and operational DFIR training.

---

## 3. Technical Domains & Forensic Modules Investigated

```
Digital Forensics Ecosystem
├── 1. Host & Disk Forensics (The Sleuth Kit, MFT, USN Journal, Registry, Event Logs)
├── 2. Network Forensics (TShark, Wireshark, Scapy, Attack Traffic Analysis)
├── 3. Mobile & IoT Chip-off (Android 10, iOS 13, Amazon Echo Show 8, Eufy Doorbell)
├── 4. AI for Forensics & CTI (Fine-Tuned LLMs, STIX 2.1 Threat Knowledge Graphs)
└── 5. Memory Forensics (Volatility RAM Dump Analysis)
```

### 3.1 Host & Filesystem Forensics
- **The Sleuth Kit (TSK):** Partition layout extraction (`mmls`), filesystem volume statistics (`fsstat`), directory inode listing (`fls`), and unallocated block carving (`icat`).
- **NIST Data Leakage Case:** Investigating enterprise intellectual property exfiltration on Windows systems. Analyzed Windows Registry hives (UserAssist, MountPoints2, USBSTOR), NTFS Master File Table (`$MFT`), and Update Sequence Number (`$UsnJrnl`) records.
- **Windows Security Event Log Analysis:** Developed automated XML parsers to extract critical audit timestamps and logon events (Event ID 4608 system startup, Event ID 4624 user logon).

### 3.2 Network Traffic Forensics
- **Packet Dissection:** Command-line capture processing using `tshark` and Wireshark.
- **Attack Reconstruction:** Investigated SYN Flood denial-of-service backlogs, SMTP spoofing header chains, ARP cache poisoning, and DNS spoofing using Python `scapy` packet manipulation scripts.
- **Wireless 802.11 Decryption:** WEP40 statistical cracking routines and GPU acceleration models.

### 3.3 Mobile & IoT Hardware Forensics
- **Android 10 (Google Pixel 3):** Reverse-lookup of application package IDs, SQLite database parsing for messaging/contacts, and Google Maps `gmm_myplaces.db` sync item extraction with coordinate conversion.
- **iOS 13.4.1 (iPhone):** Analysis of CoreDuet `knowledgeC.db` user interaction routines and location databases.
- **IoT & Hardware Chip-off Extractions:** Physical teardown and eMMC memory dump mounting for Amazon Echo Show 8 and Eufy Smart Video Doorbell, analyzing P2P communication logs and video streams.

### 3.4 AI for Forensics & Threat Intelligence (AI4Forensics)
- **Suspect Profiling:** Processing unstructured browser activity (Google Takeout Chrome JSON) into behavioral psychological profiles using LLMs.
- **Threat Intelligence Knowledge Graphs:** Mapping chat transcripts and email headers into STIX 2.1 JSON bundles and visualizing them via Graphviz DOT graphs.
- **Model Fine-Tuning for IOC Detection:** Evaluated fine-tuned classification models for identifying IP addresses and indicators within raw database dumps.

---

## 4. Engineering & Repackaging Implementation

### 4.1 Docker Containerization Architecture
To ensure platform independence across Windows, macOS, and Linux, a multi-stage `Dockerfile` and `docker-compose.yml` were engineered:
- **Base OS:** Ubuntu 22.04 LTS (x86_64)
- **Pre-installed Tooling:** The Sleuth Kit, TShark, Foremost, Binwalk, Steghide, Hashdeep, SQLite3, Libesedb, Pasco, EWF tools.
- **Python / Data Science Stack:** Scapy, STIX2, Pandas, Scikit-learn, OpenAI API, Volatility 3, JupyterLab.
- **Execution Endpoint:** Web-accessible JupyterLab server (`port 8888`) with direct workspace mounting.

### 4.2 Native WSL Kali Linux Deployment
Configured a native Linux subsystem environment utilizing Kali Linux under WSL2:
- Resolved package repository dependencies.
- Installed forensic toolchains and compiled custom utilities (`undark`, `time_decode`, `vinetto`).
- Provided one-click Windows batch launchers (`run_wsl_kali.bat`, `run_docker.bat`).

---

## 5. Automated Verification & Experimental Results

A master automated verification script ([`run_all_labs.py`](run_all_labs.py)) was authored and executed inside the WSL Kali environment to benchmark and validate the forensic modules.

### 5.1 Test Execution Output

```text
=================================================================
      DIGITAL FORENSICS LAB - AUTOMATED MASTER RUNNER
=================================================================

1. AI4Forensics: IP Identifier Evaluation
   - Test Dataset Samples: 100 SQLite log records
   - Confusion Matrix: [[33, 0], [1, 66]]
   - Accuracy:  99.00%
   - Precision: 100.00%
   - Recall:    98.51%
   - F1-Score:  0.9925  --> [SUCCESS]

2. NIST Data Leakage: Security Event Log Forensics
   - Parsed: 1,193 XML security events
   - Extracted Event IDs: 4608, 4624, 4902, 4731, 4735  --> [SUCCESS]

3. Threat Intelligence: STIX 2.1 Evidence Graphs
   - Bundle Verification: 12 STIX cyber threat indicators
   - Types: email-message, email-addr, user-account, identity,
            relationship, indicator, observable, url, incident --> [SUCCESS]

4. Mobile & IoT Datasets Integrity Audit
   - Connected Database: database.sqlite
   - Emails Table: 7,945 records
   - Persons Table: 513 records
   - Aliases Table: 850 records  --> [SUCCESS]

5. Linux Forensic CLI Tooling Verification
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

## 6. Project Artifacts & Deliverables

| File | Description |
| :--- | :--- |
| [`INTERNSHIP_REPORT.md`](INTERNSHIP_REPORT.md) | Comprehensive academic and technical internship report for Dr. Pooja Shah |
| [`LAB_GUIDE.md`](LAB_GUIDE.md) | Technical lab manual and operations reference guide |
| [`Dockerfile`](Dockerfile) | Containerized build definition with complete forensic stack |
| [`docker-compose.yml`](docker-compose.yml) | Orchestration configuration for JupyterLab & tool runtime |
| [`run_all_labs.py`](run_all_labs.py) | Master automated test suite & forensic parser runner |
| [`run_wsl_kali.bat`](run_wsl_kali.bat) | One-click Windows launcher for WSL Kali Linux workspace |
| [`run_docker.bat`](run_docker.bat) | One-click Windows launcher for Docker container build & execution |
| [`README_DOCKER.md`](README_DOCKER.md) | Deployment and maintenance documentation |

---

## 7. Conclusion & Acknowledgments

This internship provided deep practical expertise in host artifact parsing, network protocol reconstruction, IoT hardware chip-off analysis, and AI-assisted cyber threat intelligence modeling. The resulting containerized and WSL-ready environment transforms a complex, multi-gigabyte forensic repository into a streamlined, reproducible platform for academic research and operational digital forensics training.

**Acknowledgment:** Sincere gratitude to **Dr. Pooja Shah** for mentorship, guidance, and project supervision throughout this internship.
