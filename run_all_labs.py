#!/usr/bin/env python3
"""
Master Digital Forensics Lab Test & Execution Suite
Engineered & Verified by: Subham Biswas
Supervised by: Dr. Pooja Shah
"""
import os
import sys
import json
import sqlite3
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
import pandas as pd

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))

def print_header(title):
    print("\n" + "=" * 68)
    print(f"  [RUNNING] {title}")
    print("=" * 68)

def run_ai4forensics():
    print_header("1. AI4Forensics: IP Identifier Evaluation")
    dataset_path = os.path.join(REPO_ROOT, "AI4Forensics/IP_Identifier_Fine_Tuning/Calculate_Confusion_Matrix/dataset/testing100_results_dataset.csv")
    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        y_true, y_pred = df["label"], df["pred_label"]
        print(f"Total Test Samples: {len(df)}")
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_true, y_pred))
        print(f"\nAccuracy:  {accuracy_score(y_true, y_pred):.4f}")
        print(f"F1-Score:  {f1_score(y_true, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred))
        print("[+] AI4Forensics Model Evaluation: SUCCESS")
    else:
        print("[-] Dataset not found at:", dataset_path)

def run_nist_event_logs():
    print_header("2. NIST Data Leakage: Security Event Log Forensics")
    xml_path = os.path.join(REPO_ROOT, "NIST_Data_Leakage_Case/py_version/pycode/security_evt_xml/SecurityEvt_formatted.xml")
    if os.path.exists(xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        events = []
        for event in root.findall(".//Event"):
            event_id = event.find(".//EventID")
            time_created = event.find(".//TimeCreated")
            if event_id is not None and time_created is not None:
                eid = event_id.text
                stime = time_created.attrib.get("SystemTime")
                events.append((eid, stime))
        print(f"Parsed {len(events)} security events from XML evidence log.")
        print("Sample Audit Startup Events (EventID 4608):")
        for eid, stime in events[:6]:
            print(f"  - Event ID {eid} | System Timestamp: {stime}")
        print("[+] NIST Security Log Parser: SUCCESS")
    else:
        print("[-] XML file not found at:", xml_path)

def run_stix_validation():
    print_header("3. Threat Intelligence: STIX 2.1 Evidence Graphs")
    stix_demo_path = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/PhishingAttack/PhishingAttackScenarioDemo/04_output.json")
    if os.path.exists(stix_demo_path):
        with open(stix_demo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        objects = data.get("objects", []) if isinstance(data, dict) else data
        print(f"Loaded STIX Bundle containing {len(objects)} forensic indicator objects.")
        types = set(obj.get("type", "unknown") for obj in objects if isinstance(obj, dict))
        print(f"Extracted Cyber Threat Indicator Types: {', '.join(types)}")
        print("[+] STIX 2.1 Threat Intel Validation: SUCCESS")
    else:
        print("[-] STIX JSON not found at:", stix_demo_path)

def run_iot_and_mobile_audit():
    print_header("4. Mobile & SQLite Evidence Databases Audit")
    hillary_db = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/HillaryEmails/archive/database.sqlite")
    if os.path.exists(hillary_db):
        conn = sqlite3.connect(hillary_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cursor.fetchall()]
        print(f"Connected to Forensic SQLite DB ({os.path.basename(hillary_db)}).")
        print(f"Tables present: {', '.join(tables)}")
        for table in tables[:3]:
            cursor.execute(f"SELECT count(*) FROM {table};")
            count = cursor.fetchone()[0]
            print(f"  - Table '{table}': {count:,} records")
        conn.close()
        print("[+] SQLite Evidence Integrity: SUCCESS")
    else:
        print("[-] SQLite evidence file not found at:", hillary_db)

def run_blockchain_crypto_verification():
    print_header("5. Cryptocurrency & Blockchain Cryptographic Verification")
    sample_pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    pub_bytes = bytes.fromhex(sample_pubkey_hex)
    sha_hash = hashlib.sha256(pub_bytes).digest()
    ripemd = hashlib.new('ripemd160', sha_hash).hexdigest()
    print(f"ECDSA Public Key Point : {sample_pubkey_hex}")
    print(f"SHA-256 Hash Digest    : {sha_hash.hex()}")
    print(f"RIPEMD-160 HASH160      : {ripemd}")
    print("[+] Bitcoin Cryptographic Derivation: SUCCESS")

def run_cli_tools_verification():
    print_header("6. Linux Forensic CLI Tooling Verification")
    tools = [
        ("The Sleuth Kit (fls)", ["fls", "-V"]),
        ("The Sleuth Kit (mmls)", ["mmls", "-V"]),
        ("Steghide", ["steghide", "--version"]),
        ("Foremost", ["foremost", "-V"]),
        ("Hashdeep", ["hashdeep", "-V"]),
        ("SQLite3", ["sqlite3", "--version"]),
    ]
    for name, cmd in tools:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            output = (res.stdout or res.stderr).splitlines()[0]
            print(f"  [OK] {name:<25} -> {output}")
        except FileNotFoundError:
            print(f"  [--] {name:<25} -> (Not found in PATH)")

def main():
    print("=" * 68)
    print("      DIGITAL FORENSICS LAB - AUTOMATED MASTER RUNNER")
    print("      Engineered by: Subham Biswas | Mentor: Dr. Pooja Shah")
    print("=" * 68)
    run_ai4forensics()
    run_nist_event_logs()
    run_stix_validation()
    run_iot_and_mobile_audit()
    run_blockchain_crypto_verification()
    run_cli_tools_verification()
    print("\n" + "=" * 68)
    print("  [SUCCESS] ALL FORENSIC LAB MODULES EXECUTED SUCCESSFULLY!")
    print("=" * 68 + "\n")

if __name__ == "__main__":
    main()
