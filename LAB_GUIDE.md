# Digital Forensics Lab Handbook & Technical Guide

This handbook provides an index of the hands-on lab modules, tool setups, and forensic workflows contained in this repository.

---

## 🛠️ Lab Environment & Tool Requirements

The exercises utilize standard open-source digital forensic utilities and Python libraries:

| Category | Primary Tools |
| :--- | :--- |
| **Disk & Filesystem Forensics** | The Sleuth Kit (`fls`, `icat`, `istat`, `mmls`, `fsstat`), `pasco`, `ewf-tools` |
| **Network Forensics** | Wireshark, `tshark`, `tcpdump`, Python `scapy` |
| **Artifact Parsers** | `evtx_dump.py`, `time_decode.py`, `prefetch.py`, `undark`, `liblnk-utils`, `libesedb-utils` |
| **Data Carving & Steganography** | `foremost`, `binwalk`, `steghide`, `stegdetect` |
| **Memory Analysis** | `volatility3`, `yara` |
| **AI & Threat Intelligence** | Python (`pandas`, `scikit-learn`, `stix2`, `openai`, `jupyterlab`) |

---

## 📚 Curriculum & Lab Modules

### 1. Fundamental Forensics & Tooling (`Basic_Computer_Skills_for_Forensics/`)
- **Number Systems:** Binary, hexadecimal, byte ordering (endianness), and data structure alignment.
- **Disk Analysis:** Partition table parsing with `mmls` and raw filesystem traversal with `fls` and `icat`.
- **Data Carving:** Header/footer carving for deleted file recovery (`foremost`, `scalpel`).
- **Steganography:** Detecting hidden payloads in bitmap and JPEG images (`steghide`).

### 2. Network Forensics (`Networking_Forensics/` & `Email_Harassment/`)
- **Traffic Analysis:** Filtering protocols, streams, and suspicious connections using `tshark`.
- **Attack Investigation:** 
  - SYN Flood analysis and connection backlog saturation.
  - SMTP email packet dissection and header spoofing detection.
  - ARP Poisoning and DNS Spoofing packet reconstruction.
  - 802.11 WEP40 packet decryption.

### 3. Enterprise Case Studies (`NIST_Data_Leakage_Case/` & `P2P_Leakage/`)
- **NIST Data Leakage Case (Windows XP):**
  - Windows Registry hive analysis (UserAssist, MountPoints2, USBSTOR).
  - Event Log parsing (`.evt`/`.evtx`) to identify logon sessions and service changes.
  - Web browser artifacts (IE history, search queries, cache carving).
  - NTFS USN Journal and volume shadow copy analysis.
- **P2P Data Leakage Case (Windows 10):**
  - Master File Table (`$MFT`) timeline reconstruction.
  - BitTorrent client artifacts (`resume.dat` and `.torrent` metadata).
  - Memory analysis of active file transfers using Volatility.

### 4. Mobile & IoT Forensics (`Android10/`, `iOS/`, `Echo_Device/`, `Eufy_Doorbell/`)
- **Android 10 (Google Pixel 3):**
  - SQLite database parsing for stock apps (SMS, Contacts, Calendar).
  - Google Maps `gmm_myplaces.db` sync item extraction and GPS coordinate conversion.
  - Third-party app data structures (WhatsApp, Kik, TextNow).
- **iOS 13 (iPhone):**
  - `knowledgeC.db` user interaction routines and application usage patterns.
  - CoreDuet and location caching databases (`consolidated.db`).
- **Smart Devices & Hardware Forensics:**
  - Amazon Echo Show 8: eMMC chip-off extraction, network configurations, and multimedia caches.
  - Eufy Smart Doorbell: P2P communication log analysis and camera video fragments.
  - DJI Mavic Air Drone: Flight telemetry, GPS waypoints, and EXIF coordinate mapping.

### 5. AI for Forensics (`AI4Forensics/`)
- **Suspect Profiling:** Processing raw Google Takeout browser history into behavioral profiles using LLMs.
- **Automated STIX Graph Generation:** Converting chat logs and email threads into STIX 2.1 threat intelligence graph visualisations.
- **Forensic Indicator Fine-Tuning:** Training and evaluating classification models on unstructured SQLite logs to extract IP addresses and IOCs.

---

## ⚡ Quick Execution Reference

### Running Security Event Log Analysis
```powershell
cd NIST_Data_Leakage_Case\py_version\pycode\security_evt_xml
python securityevt_findall_eventid_time.py
```

### Running AI IP Model Evaluation
```powershell
python -c "from sklearn.metrics import classification_report; import pandas as pd; df = pd.read_csv('AI4Forensics/IP_Identifier_Fine_Tuning/Calculate_Confusion_Matrix/dataset/testing100_results_dataset.csv'); print(classification_report(df['label'], df['pred_label']))"
```

### Launching JupyterLab
```powershell
jupyter lab
```
