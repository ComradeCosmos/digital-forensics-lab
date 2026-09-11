#!/bin/bash
# Digital Forensics Lab - Linux Live Demo Script
# Engineered by: Subham Biswas | Mentor: Dr. Pooja Shah

OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

echo "====================================================="
echo "  🛡️ DIGITAL FORENSICS LAB - LINUX DEMO & EXECUTION"
echo "  User: $(whoami) | OS: ${OS_NAME}"
echo "====================================================="
echo ""
echo "[1] Digital Forensics Utilities Verification:"
echo " - The Sleuth Kit (fls):  $(fls -V 2>&1 | head -n 1)"
echo " - The Sleuth Kit (mmls): $(mmls -V 2>&1 | head -n 1)"
echo " - Steghide:              $(steghide --version 2>&1 | head -n 1)"
echo " - Foremost Carving:      $(foremost -V 2>&1 | head -n 1)"
echo " - Hashdeep Hashing:      $(hashdeep -V 2>&1 | head -n 1)"
echo " - Binwalk Analyzer:      $(binwalk --help 2>&1 | head -n 2 | tail -n 1 | xargs)"
echo " - SQLite3 Engine:        $(sqlite3 --version 2>&1 | head -n 1)"
echo ""
echo "[2] Running Master Automated Lab Suite:"
python3 run_all_labs.py
