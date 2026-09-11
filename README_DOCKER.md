# Digital Forensics Lab - Containerized Distribution

**Packaged & Maintained by:** Subham Biswas  
**Upstream Lab Curriculum & Content:** Frank W. Xu (University of Baltimore / Towson University)  
**License:** [Apache License 2.0](LICENSE)

---

## 🚀 Quick Start with Docker

This environment bundles all necessary command-line forensics utilities (The Sleuth Kit, TShark, Volatility 3, Pasco, Binwalk, Steghide, Hashdeep, Evtx/Lnk/Prefetch parsers) and a complete Python/Jupyter data science stack.

### 1. Build & Run Container
To start the container with full interactive Jupyter Lab and bash access:

```bash
docker compose up -d --build
```

Or on Windows:
```cmd
run_docker.bat
```

### 2. Access the Jupyter Environment
Open your browser and navigate to:
- **URL:** [http://localhost:8888/?token=forensics](http://localhost:8888/?token=forensics)
- All `.ipynb` notebooks in `AI4Forensics/`, `NIST_Data_Leakage_Case/`, etc., can be opened and run directly.

### 3. Interactive CLI Access
To access the command line inside the container:

```bash
docker exec -it digital_forensics_lab bash
```

Inside the container, you have immediate access to:
- `fls`, `icat`, `mmls`, `fsstat` (The Sleuth Kit)
- `tshark`, `tcpdump`
- `vol` / `volatility3`
- `foremost`, `binwalk`, `hashdeep`
- `evtx_dump.py`, `time_decode.py`, `prefetch.py`, `undark`
- Python 3 with `scapy`, `stix2`, `pandas`, `sklearn`, `openai`

---

## 📁 Repository Labs Included

1. **Fundamental Digital Forensics:** Sleuth Kit, disk image acquisition, data carving, and steganography.
2. **Network Forensics:** Wireshark/TShark, SYN flood detection, ARP & DNS spoofing analysis, and WEP cracking.
3. **Enterprise Case Studies:** NIST Windows XP Data Leakage, Windows 10 P2P BitTorrent leakage, and Volatility RAM analysis.
4. **Mobile & IoT Forensics:** Android 10 (Pixel 3), iOS 13 (iPhone), Amazon Echo Show 8 eMMC chip-off, and Eufy Smart Doorbell extractions.
5. **AI for Forensics:** Suspect profiling via LLMs, automated STIX 2.1 graph creation, and fine-tuned AI indicator detection.
