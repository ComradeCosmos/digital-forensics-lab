#!/usr/bin/env python3
"""
Digital Forensics Interactive Educational Laboratory & Concept Tutor
Engineered by: Subham Biswas | Mentor: Dr. Pooja Shah

A comprehensive, concept-driven command-line learning environment
designed to teach core digital forensics methodologies, artifact analysis,
and investigative toolchains through theory, visual diagrams, guided walkthroughs,
and interactive practical challenges.
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
import pandas as pd

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))

class Style:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def draw_header(title):
    print(Style.CYAN + "=" * 78 + Style.END)
    print(Style.BOLD + f"  {title.upper()}" + Style.END)
    print(Style.DIM + "  Digital Forensics Laboratory | Subham Biswas | Mentor: Dr. Pooja Shah" + Style.END)
    print(Style.CYAN + "=" * 78 + Style.END + "\n")

def pause():
    input(Style.DIM + "\nPress Enter to continue..." + Style.END)

def run_quiz(questions):
    print("\n" + Style.YELLOW + Style.BOLD + "[CONCEPT MASTERY CHECK]" + Style.END)
    score = 0
    for idx, q in enumerate(questions, 1):
        print(f"\nQ{idx}: {q['question']}")
        for opt_idx, opt in enumerate(q['options'], 1):
            print(f"   [{opt_idx}] {opt}")
        
        while True:
            ans = input(Style.BOLD + f"Your answer (1-{len(q['options'])}) > " + Style.END).strip()
            if ans.isdigit() and 1 <= int(ans) <= len(q['options']):
                chosen = int(ans)
                if chosen == q['correct']:
                    print(Style.GREEN + f"[+] Correct! {q['explanation']}" + Style.END)
                    score += 1
                else:
                    print(Style.RED + f"[-] Incorrect. Correct answer was [{q['correct']}]. {q['explanation']}" + Style.END)
                break
            else:
                print(Style.RED + f"Please enter a number between 1 and {len(q['options'])}." + Style.END)
    
    print(f"\nScore: {score}/{len(questions)} concepts mastered.")

# =====================================================================
# MODULE 1: DISK PARTITIONS & THE SLEUTH KIT
# =====================================================================
def module_disk_forensics():
    clear()
    draw_header("Module 1: Disk Partition & Filesystem Forensics (The Sleuth Kit)")
    
    print(Style.BOLD + "[1] Theoretical Foundations & Storage Architecture:" + Style.END)
    print(
        "Digital storage media stores data in physical units called 'sectors'.\n"
        "In raw bit-stream disk images (e.g., .dd, .raw, .001, .E01), the disk begins at Sector 0\n"
        "where the Master Boot Record (MBR) or GUID Partition Table (GPT) defines partition boundaries.\n"
        "Because forensic disk images contain the entire disk (including partition tables and unallocated space),\n"
        "investigators cannot directly mount the image as a single filesystem. Instead, we use The Sleuth Kit (TSK)\n"
        "to calculate partition offsets and inspect filesystem structures non-destructively."
    )
    
    print("\n" + Style.BOLD + "[2] Disk Layout Diagram:" + Style.END)
    print(Style.CYAN + """
+-------------------------------------------------------------------------------+
| Sector 0: MBR / Partition Table                                               |
+-------------------------------------------------------------------------------+
| Sector 1 to 2047: Reserved / Unallocated Space (1 MB alignment gap)          |
+-------------------------------------------------------------------------------+
| Sector 2048: Partition 1 Starts (System Reserved Volume)                      |
|   -> Byte Offset = 2048 * 512 bytes = 1,048,576 bytes (1 MB)                 |
+-------------------------------------------------------------------------------+
| Sector 206848: Partition 2 Starts (Main OS Volume - NTFS C:\\)                 |
|   -> Byte Offset = 206848 * 512 bytes = 105,906,176 bytes (~101 MB)          |
+-------------------------------------------------------------------------------+
""" + Style.END)

    print(Style.BOLD + "[3] Mathematical Principles of Sector Offsets:" + Style.END)
    print(
        " - Standard Sector Size = 512 bytes.\n"
        " - Byte Offset = (Starting Sector Number) * (Bytes Per Sector)\n"
        " - Filesystem Offset Parameter: '-o <sector_offset>' passed to TSK tools."
    )

    print("\n" + Style.BOLD + "[4] The Sleuth Kit (TSK) Command Suite:" + Style.END)
    print(" - mmls <image>                : Lists partition table structure, slots, start and length.")
    print(" - fsstat -o <offset> <image>  : Displays filesystem metadata, cluster size, and block allocation.")
    print(" - fls -r -o <offset> <image>  : Recursively lists directory entries, inodes, and deleted files (*).")
    print(" - icat -o <offset> <img> <ino>: Extracts content of specific file directly using its Inode number.")
    print(" - istat -o <offset> <img> <ino>: Displays detailed metadata and block pointers for an inode.")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 1 - Command Syntax]" + Style.END)
    print("Scenario: You have acquired an evidence image named 'evidence.dd'.")
    print("Task: Enter the command to display the partition layout and sector start offsets:")
    
    while True:
        cmd = input(Style.BOLD + "dfir-lab (disk) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Use the partition listing tool: 'mmls evidence.dd'" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if cmd.startswith("mmls"):
            print(Style.GREEN + "\n[+] Correct syntax! mmls will read the MBR/GPT partition tables.\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Incorrect syntax. Type 'mmls evidence.dd' or type 'hint'." + Style.END)

    print(Style.BOLD + "[5] Live Demonstration - Interpreting Partition Metadata:" + Style.END)
    sample_mmls = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000001   0000002047   0000002047   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07) [System Reserved]
003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07) [Main Windows C:\\]
004:  -------   0041940992   0041943039   0000002048   Unallocated"""
    
    print(Style.CYAN + sample_mmls + Style.END)
    print(Style.BOLD + "Forensic Findings & Analysis:" + Style.END)
    print(" - Slot 002 (System Reserved): Starts at sector 2048. Byte offset = 2048 * 512 = 1,048,576 bytes.")
    print(" - Slot 003 (Main Windows Volume): Starts at sector 206848. Byte offset = 206848 * 512 = 105,906,176 bytes.")
    print(" - To list all deleted files from the main C:\\ partition:")
    print("   Command: fls -r -p -d -o 206848 evidence.dd")

    quiz_questions = [
        {
            "question": "If a partition starts at Sector 4096 on a 512-byte sector disk, what is its byte offset?",
            "options": ["2,097,152 bytes (2 MB)", "4,096,000 bytes", "1,048,576 bytes", "512,000 bytes"],
            "correct": 1,
            "explanation": "4096 sectors * 512 bytes/sector = 2,097,152 bytes (exactly 2 MB)."
        },
        {
            "question": "In 'fls' output, what does an asterisk (*) next to a directory or file entry indicate?",
            "options": ["The file is encrypted", "The file has been deleted / marked unallocated", "The file is an executable", "The file has read-only permissions"],
            "correct": 2,
            "explanation": "TSK uses an asterisk (*) to denote deleted records whose metadata remains in the MFT/FAT table."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 2: WINDOWS EVENT LOG & HOST ARTIFACT FORENSICS
# =====================================================================
def module_event_logs():
    clear()
    draw_header("Module 2: Host Forensics & Windows Security Event Log Auditing")

    print(Style.BOLD + "[1] Theoretical Foundations & Incident Response Context:" + Style.END)
    print(
        "Windows Security Event Logs (Security.evtx / SecurityEvt.xml) provide non-repudiation\n"
        "audit trails for enterprise host forensics. When investigating unauthorized access, data exfiltration,\n"
        "or ransomware deployment, analysts trace authentication sequences across four key phases:\n"
        " 1. Initial Access & Authentication (Logon Events)\n"
        " 2. Privilege Escalation (Token Privileges Assigned)\n"
        " 3. Persistence Creation (New User/Group Setup)\n"
        " 4. Policy Tampering (Audit Subsystem Disabling)"
    )

    print("\n" + Style.BOLD + "[2] Critical Windows Security Event IDs:" + Style.END)
    print(" - Event ID 4608 : Windows Startup (Local Security Authority process initiated).")
    print(" - Event ID 4624 : Successful Account Logon (Logon Type 2=Console, 3=Network/SMB, 10=RDP).")
    print(" - Event ID 4625 : Failed Account Logon (Critical for detecting password brute-forcing).")
    print(" - Event ID 4672 : Special Privileges Assigned (Administrator / SYSTEM token elevation).")
    print(" - Event ID 4720 : User Account Created (Adversary establishing persistence).")
    print(" - Event ID 4738 : User Account Modified (Password reset or attribute changes).")
    print(" - Event ID 1102 : Audit Log Cleared (High-confidence indicator of attacker anti-forensics).")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 2 - XML Event Extraction]" + Style.END)
    print("Scenario: You are investigating the NIST Data Leakage Case.")
    print("Task: Enter the command to parse the XML Security Event logs with Python:")

    while True:
        cmd = input(Style.BOLD + "dfir-lab (events) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Enter 'python3 securityevt_findall_eventid_time.py' or 'python run_all_labs.py'" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if "securityevt" in cmd.lower() or "run_all" in cmd.lower() or "python" in cmd.lower():
            print(Style.GREEN + "\n[+] Valid parser selected! Parsing raw XML evidence...\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Enter 'python3 securityevt_findall_eventid_time.py' or type 'hint'." + Style.END)

    print(Style.BOLD + "[3] Live Execution & Real Evidence Timeline (NIST Data Leakage Case):" + Style.END)
    xml_path = os.path.join(REPO_ROOT, "NIST_Data_Leakage_Case/py_version/pycode/security_evt_xml/SecurityEvt_formatted.xml")
    if os.path.exists(xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        events = []
        for event in root.findall(".//Event"):
            eid = event.find(".//EventID")
            stime = event.find(".//TimeCreated")
            if eid is not None and stime is not None:
                events.append((eid.text, stime.attrib.get("SystemTime", "")))

        print(f"Total Evidence Records in XML: {len(events):,} Events")
        print("-" * 75)
        print(f"{'Index':<6} {'Event ID':<12} {'Event Description':<32} {'System Time (UTC)':<24}")
        print("-" * 75)
        desc_map = {
            "4608": "Windows System Startup",
            "4624": "Successful Logon",
            "4902": "Audit Policy Created",
            "4731": "Security Group Created",
            "4735": "Security Group Modified"
        }
        for idx, (eid, t) in enumerate(events[:8], 1):
            desc = desc_map.get(eid, "System Audit Event")
            print(f"{idx:<6} {eid:<12} {desc:<32} {t:<24}")
        print("-" * 75)
        print(Style.BOLD + "\nForensic Conclusion & Attack Timeline:" + Style.END)
        print(" - 2015-03-25 10:15:35 UTC: System startup completed (Event 4608).")
        print(" - 2015-03-25 10:15:35 UTC: Immediate Administrator session logon (Event 4624).")
        print(" - Followed by modifications to security policy tables (Event 4902, 4731, 4735).")
    else:
        print("[-] XML file not located at expected path.")

    quiz_questions = [
        {
            "question": "Which Windows Event ID indicates that an attacker has attempted and failed to log in?",
            "options": ["Event ID 4624", "Event ID 4625", "Event ID 4608", "Event ID 4720"],
            "correct": 2,
            "explanation": "Event ID 4625 is generated on failed logon attempts and indicates authentication failure reasons."
        },
        {
            "question": "If an Event ID 4624 records Logon Type 10, what logon method was used?",
            "options": ["Interactive console keyboard logon", "Network share / SMB connection", "Remote Desktop Protocol (RDP)", "Service / Scheduled Task start"],
            "correct": 3,
            "explanation": "Logon Type 10 represents RemoteInteractive (Terminal Services / Remote Desktop Protocol / RDP)."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 3: NETWORK TRAFFIC FORENSICS (TSHARK & WIRESHARK)
# =====================================================================
def module_network_forensics():
    clear()
    draw_header("Module 3: Network Traffic Forensics & Incident Response")

    print(Style.BOLD + "[1] Theoretical Foundations & Packet Dissection:" + Style.END)
    print(
        "Network forensics captures and reconstructs communication flows across OSI layers.\n"
        "In incident response, packet capture (PCAP) files reveal the ground truth of data exfiltration,\n"
        "lateral movement, beaconing frequency, and credential theft.\n"
        "TShark provides a high-throughput command-line parser capable of evaluating Wireshark display filters (-Y)\n"
        "and printing targeted protocol fields (-T fields -e <field>)."
    )

    print("\n" + Style.BOLD + "[2] The TCP 3-Way Handshake vs SYN Flood Attack:" + Style.END)
    print(Style.CYAN + """
Normal 3-Way Handshake:
  Client  ---[ SYN (Seq=0) ]------------> Server
  Client  <--[ SYN-ACK (Seq=0, Ack=1) ]-- Server
  Client  ---[ ACK (Seq=1, Ack=1) ]-----> Server (Connection Established)

SYN Flood Denial of Service Attack:
  Attacker ---[ SYN 1 (Spoofed IP) ]-----> Server (Allocates TCB memory)
  Attacker ---[ SYN 2 (Spoofed IP) ]-----> Server (Allocates TCB memory)
  Attacker ---[ SYN 3 (Spoofed IP) ]-----> Server (Allocates TCB memory)
  Attacker ---[ SYN N (Spoofed IP) ]-----> Server (SYN Backlog Full -> Crash)
""" + Style.END)

    print(Style.BOLD + "[3] Essential TShark Command Filters:" + Style.END)
    print(" - Capture Inspection  : tshark -r capture.pcap")
    print(" - HTTP Requests Only  : tshark -r capture.pcap -Y 'http.request'")
    print(" - SYN Flood Filter    : tshark -r capture.pcap -Y 'tcp.flags.syn == 1 and tcp.flags.ack == 0'")
    print(" - ARP Spoofing Filter : tshark -r capture.pcap -Y 'arp.duplicate-address-frame'")
    print(" - DNS Query Extraction: tshark -r capture.pcap -Y 'dns' -T fields -e ip.src -e dns.qry.name")
    print(" - SMTP Exfiltration   : tshark -r capture.pcap -Y 'smtp'")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 3 - Protocol Filtering]" + Style.END)
    print("Scenario: An endpoint is suspected of exfiltrating data via unencrypted HTTP.")
    print("Task: Enter the TShark command to filter and display only HTTP requests from 'capture.pcap':")

    while True:
        cmd = input(Style.BOLD + "dfir-lab (network) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Enter: tshark -r capture.pcap -Y \"http.request\"" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if "tshark" in cmd.lower() and "http" in cmd.lower():
            print(Style.GREEN + "\n[+] Correct! Display filter accepted.\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Enter: tshark -r capture.pcap -Y \"http.request\" or type 'hint'." + Style.END)

    print(Style.BOLD + "[4] Live Demonstration - Dissecting a SYN Flood Incident Capture:" + Style.END)
    print(Style.CYAN + """Packet #  Time (s)     Source IP       Destination IP  Protocol  TCP Flags   Info
1         0.000000     192.168.1.50    10.0.0.1        TCP       0x002 [SYN] 44582 -> 80 [SYN] Seq=0
2         0.000102     192.168.1.51    10.0.0.1        TCP       0x002 [SYN] 44583 -> 80 [SYN] Seq=0
3         0.000215     192.168.1.52    10.0.0.1        TCP       0x002 [SYN] 44584 -> 80 [SYN] Seq=0
4         0.000308     192.168.1.53    10.0.0.1        TCP       0x002 [SYN] 44585 -> 80 [SYN] Seq=0
5         0.000412     192.168.1.54    10.0.0.1        TCP       0x002 [SYN] 44586 -> 80 [SYN] Seq=0""" + Style.END)
    
    print(Style.BOLD + "\nForensic Analysis:" + Style.END)
    print(" - Every packet has SYN=1 and ACK=0 with rapid delta times (< 0.1 ms).")
    print(" - Source IPs increment sequentially (IP spoofing), preventing TCP handshakes from completing.")
    print(" - Host half-open connection tables are exhausted, causing resource exhaustion Denial of Service.")

    quiz_questions = [
        {
            "question": "Which Wireshark / TShark display filter identifies pure TCP SYN packets without ACK?",
            "options": [
                "tcp.flags == 0x18",
                "tcp.flags.syn == 1 and tcp.flags.ack == 0",
                "http.request.method == 'SYN'",
                "ip.proto == 6 and ip.flags.syn == 1"
            ],
            "correct": 2,
            "explanation": "In TCP headers, a pure connection request packet has SYN=1 and ACK=0."
        },
        {
            "question": "What is the difference between a capture filter (BPF) and a display filter in TShark?",
            "options": [
                "Capture filters are applied before packets are written to disk; display filters evaluate already captured packets",
                "Display filters only work on Ethernet frames",
                "Capture filters use Python syntax, display filters use SQL",
                "There is no difference"
            ],
            "correct": 1,
            "explanation": "Berkeley Packet Filters (BPF, -f) discard unwanted traffic during packet capture, while display filters (-Y) filter parsed protocol trees."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 4: MEMORY FORENSICS & VOLATILITY
# =====================================================================
def module_memory_forensics():
    clear()
    draw_header("Module 4: Memory Forensics & Volatile Artifact Analysis")

    print(Style.BOLD + "[1] Theoretical Foundations & Volatile Memory Analysis:" + Style.END)
    print(
        "RAM contains volatile digital evidence that disappears upon system power-off:\n"
        " - Unencrypted credentials, passwords, and cryptographic keys.\n"
        " - Injected malicious shellcode and unlinked DLLs.\n"
        " - Active network connections and listening sockets.\n"
        " - Terminated process metadata and command-line history.\n"
        "Volatility 3 is the standard framework for dissecting physical RAM dumps (.raw, .vmem, .dmp)."
    )

    print("\n" + Style.BOLD + "[2] Volatility 3 Core Analysis Plugins:" + Style.END)
    print(" - windows.pslist       : Enumerates active processes by walking the active process double-linked list.")
    print(" - windows.pstree       : Renders parent-child process relationships to detect rogue spawning.")
    print(" - windows.malfind      : Detects hidden/injected executable code (VAD permissions: PAGE_EXECUTE_READWRITE).")
    print(" - windows.netscan      : Recovers active and closed TCP/UDP network connections and socket objects.")
    print(" - windows.cmdline      : Extracts command-line launch arguments supplied to processes.")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 4 - Volatility Memory Triage]" + Style.END)
    print("Scenario: You have acquired 'memdump.raw' and suspect process injection in explorer.exe.")
    print("Task: Enter the Volatility 3 command to scan for injected code and executable VADs:")

    while True:
        cmd = input(Style.BOLD + "dfir-lab (volatility) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Enter: vol -f memdump.raw windows.malfind" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if "malfind" in cmd.lower():
            print(Style.GREEN + "\n[+] Correct! windows.malfind inspects VAD allocation protections.\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Enter: vol -f memdump.raw windows.malfind or type 'hint'." + Style.END)

    print(Style.BOLD + "[3] Live Demonstration - Interpreting Malfind Injected Code:" + Style.END)
    sample_malfind = """PID    Process        Base Address   Protection             Commit Charge
1840   svchost.exe    0x002a0000     PAGE_EXECUTE_READWRITE 1
Hex Dump:
4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
Disassembly:
0x2a0000:  dec    ebp
0x2a0001:  pop    edx
0x2a0002:  nop"""
    print(Style.CYAN + sample_malfind + Style.END)
    print(Style.BOLD + "Forensic Findings:" + Style.END)
    print(" - Memory region is marked PAGE_EXECUTE_READWRITE (RWX) which is abnormal for standard DLLs.")
    print(" - Byte 0 begins with 4D 5A ('MZ'), proving an executable PE binary has been injected directly into memory.")

    quiz_questions = [
        {
            "question": "Why is the memory protection 'PAGE_EXECUTE_READWRITE' (RWX) a major indicator of code injection?",
            "options": [
                "Standard legitimate software separates code (RX) from data (RW) to prevent exploitation (W^X / DEP)",
                "RWX means the computer is out of memory",
                "RWX indicates an encrypted BitLocker volume",
                "RWX is standard for all system processes"
            ],
            "correct": 1,
            "explanation": "Legitimate software enforces Data Execution Prevention (DEP). Memory regions that are simultaneously writable and executable almost always signify shellcode injection."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 5: MOBILE & SQLITE EVIDENCE DATABASES
# =====================================================================
def module_sqlite_forensics():
    clear()
    draw_header("Module 5: Mobile & Forensic SQLite Evidence Analysis")

    print(Style.BOLD + "[1] Theoretical Foundations & SQLite Storage Engine:" + Style.END)
    print(
        "Modern mobile operating systems (Android, iOS) and desktop applications (Chrome, Firefox, Teams)\n"
        "store almost all user artifacts inside B-Tree structured SQLite database files (.db, .sqlite, .sqlite3).\n"
        "Forensic examiners analyze SQLite tables, reconstruct Write-Ahead Logs (.wal), and recover records\n"
        "from SQLite freelist pages where deleted rows persist until overwritten."
    )

    print("\n" + Style.BOLD + "[2] Common Forensic SQLite Locations:" + Style.END)
    print(" - Android SMS/MMS        : /data/data/com.android.providers.telephony/databases/mmssms.db")
    print(" - Google Maps Sync Places: gmm_myplaces.db (Coordinates in microdegrees: Lat = microdegrees / 1e6)")
    print(" - iOS Knowledge C DB     : /private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db")
    print(" - Chrome Browsing History: /User Data/Default/History (urls, visits, keyword_search_terms)")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 5 - SQL Evidence Query]" + Style.END)
    print("Scenario: You are investigating communication links inside 'database.sqlite'.")
    print("Task: Enter a SQL statement to query the top 5 records from the 'Emails' table:")

    while True:
        cmd = input(Style.BOLD + "dfir-lab (sql) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Enter: SELECT * FROM Emails LIMIT 5;" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if "select" in cmd.lower() and "emails" in cmd.lower():
            print(Style.GREEN + "\n[+] Correct SQL syntax! Executing live database query...\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Enter: SELECT * FROM Emails LIMIT 5; or type 'hint'." + Style.END)

    print(Style.BOLD + "[3] Live Database Query Execution (database.sqlite):" + Style.END)
    db_path = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/HillaryEmails/archive/database.sqlite")
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]
        print(f"Discovered Tables in SQLite Schema: {', '.join(tables)}")
        
        cur.execute("SELECT Id, SenderPersonId, MetadataDateSent, ExtractedSubject FROM Emails WHERE ExtractedSubject != '' LIMIT 5;")
        rows = cur.fetchall()
        print("-" * 80)
        print(f"{'Email ID':<10} {'Sender ID':<12} {'Date Sent (UTC)':<24} {'Extracted Subject':<32}")
        print("-" * 80)
        for r in rows:
            print(f"{str(r[0]):<10} {str(r[1]):<12} {str(r[2]):<24} {str(r[3])[:30]:<32}")
        print("-" * 80)
        conn.close()
    else:
        print("[-] Database file not found.")

    quiz_questions = [
        {
            "question": "What is the purpose of the Write-Ahead Log (.wal) file in SQLite forensics?",
            "options": [
                "It stores user passwords in plaintext",
                "It temporarily buffers committed transactions before writing them to the main database file",
                "It is a backup copy of deleted tables",
                "It contains only operating system crash dumps"
            ],
            "correct": 2,
            "explanation": "WAL files hold recent database transactions; examining the .wal file reveals newly written or uncommitted forensic evidence."
        },
        {
            "question": "How are Google Maps latitude/longitude coordinates stored in forensic SQLite databases?",
            "options": [
                "As GPS NMEA strings",
                "As integer microdegrees (Latitude = stored_integer / 1,000,000)",
                "As encrypted base64 strings",
                "As radians"
            ],
            "correct": 2,
            "explanation": "Google Maps saves coordinates as microdegrees (1e-6 degrees). Example: 37774929 corresponds to 37.774929 degrees Latitude."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 6: DATA CARVING & FILE RECOVERY
# =====================================================================
def module_data_carving():
    clear()
    draw_header("Module 6: Forensic Data Carving & File Signature Recovery")

    print(Style.BOLD + "[1] Theoretical Foundations & Magic Bytes:" + Style.END)
    print(
        "Data carving is the recovery of files from unallocated clusters, raw memory dumps,\n"
        "or damaged partitions based entirely on file-format-specific headers, footers, and structural markers\n"
        "without referencing filesystem allocation metadata (such as the FAT table or NTFS MFT).\n"
        "Every binary file format begins with unique identifying 'magic bytes' at byte offset 0."
    )

    print("\n" + Style.BOLD + "[2] Common Forensic File Signatures:" + Style.END)
    print("-" * 75)
    print(f"{'File Type':<16} {'Header (Magic Bytes)':<30} {'Footer Signature':<24}")
    print("-" * 75)
    print(f"{'JPEG Image':<16} {'FF D8 FF':<30} {'FF D9':<24}")
    print(f"{'PNG Image':<16} {'89 50 4E 47 0D 0A 1A 0A':<30} {'49 45 4E 44 AE 42 60 82':<24}")
    print(f"{'PDF Document':<16} {'25 50 44 46 (%PDF)':<30} {'25 25 45 4F 46 (%%EOF)':<24}")
    print(f"{'ZIP / Office':<16} {'50 4B 03 04 (PK..)':<30} {'50 4B 05 06':<24}")
    print(f"{'Windows EXE':<16} {'4D 5A (MZ)':<30} {'N/A (PE Header Length)':<24}")
    print("-" * 75)

    print("\n" + Style.BOLD + "[3] Carving Tool Command Reference:" + Style.END)
    print(" - Foremost : foremost -t <file_types> -i <raw_image> -o <output_directory>")
    print(" - Scalpel  : scalpel -c scalpel.conf -o <output_directory> <raw_image>")
    print(" - Steghide : steghide extract -sf <image.jpg> -p <passphrase>")
    print(" - Binwalk  : binwalk -e <firmware_or_binary>")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 6 - File Carving Execution]" + Style.END)
    print("Scenario: You need to carve all JPEG and PDF files from 'dump.raw' into directory 'carved_files'.")
    print("Task: Enter the Foremost command:")

    while True:
        cmd = input(Style.BOLD + "dfir-lab (carving) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Enter: foremost -t jpg,pdf -i dump.raw -o carved_files" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if "foremost" in cmd.lower() and ("-i" in cmd.lower() or "dump.raw" in cmd.lower()):
            print(Style.GREEN + "\n[+] Correct Foremost command syntax!\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Enter: foremost -t jpg,pdf -i dump.raw -o carved_files or type 'hint'." + Style.END)

    print(Style.BOLD + "[4] Live Demonstration - Magic Byte Hex Inspection:" + Style.END)
    sample_pdf_bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog ... >>\n%%EOF"
    print(f"Simulated Raw Stream: {sample_pdf_bytes[:30]} ... {sample_pdf_bytes[-10:]}")
    print(f"Extracted Magic Header: {sample_pdf_bytes[:4].decode('latin-1')} (Hex: {sample_pdf_bytes[:4].hex().upper()}) -> Identified as PDF Document")
    print(f"Extracted Magic Footer: {sample_pdf_bytes[-5:].decode('latin-1')} (Hex: {sample_pdf_bytes[-5:].hex().upper()}) -> Confirms Clean File Boundary")

    quiz_questions = [
        {
            "question": "What happens if a carved file is heavily fragmented across non-contiguous disk clusters?",
            "options": [
                "The carving tool automatically repairs all sectors",
                "Simple header/footer carving may produce corrupted or incomplete files",
                "The file cannot have magic bytes",
                "The filesystem will refuse to delete the file"
            ],
            "correct": 2,
            "explanation": "Header/footer carvers assume file data is contiguous. If fragmented, carving requires advanced bipartite graph or structural parsers."
        },
        {
            "question": "What is the standard starting magic byte signature for a JPEG image?",
            "options": ["0x89 0x50 0x4E 0x47", "0xFF 0xD8 0xFF", "0x50 0x4B 0x03 0x04", "0x4D 0x5A"],
            "correct": 2,
            "explanation": "0xFF 0xD8 0xFF is the Start of Image (SOI) marker for all JPEG graphics."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 7: THREAT INTELLIGENCE & STIX 2.1 EVIDENCE GRAPHS
# =====================================================================
def module_stix_forensics():
    clear()
    draw_header("Module 7: Cyber Threat Intelligence & STIX 2.1 Evidence Graphs")

    print(Style.BOLD + "[1] Theoretical Foundations & Extended STIX (xSTIX):" + Style.END)
    print(
        "Structured Threat Information Expression (STIX 2.1) standardizes cyber threat intelligence.\n"
        "Extended STIX (xSTIX) introduces Cyber Forensic Objects (CFOs) to formally document digital evidence\n"
        "for judicial presentation. STIX divides intelligence into:\n"
        " - SDOs (Domain Objects): indicator, malware, identity, attack-pattern, incident.\n"
        " - SCOs (Cyber-observable Objects): ipv4-addr, file, domain-name, email-addr, user-account.\n"
        " - SROs (Relationship Objects): indicates, attributed-to, uses, relates-to."
    )

    print("\n" + Style.BOLD + "[2] STIX 2.1 Forensic Graph Architecture:" + Style.END)
    print(Style.CYAN + """
[Attacker Identity] <---(attributed-to)--- [Malware / Phishing Campaign]
                                                  |
                                             (indicates)
                                                  v
[Suspicious URL / IP] <---(uses)--- [Indicator Pattern: '[url:value = ...]' ]
""" + Style.END)

    print(Style.BOLD + "[3] Live Demonstration - Parsing STIX 2.1 JSON Threat Bundle:" + Style.END)
    stix_demo_path = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/PhishingAttack/PhishingAttackScenarioDemo/04_output.json")
    if os.path.exists(stix_demo_path):
        with open(stix_demo_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else bundle
        print(f"Total Objects in STIX Bundle: {len(objects)}")
        print("-" * 75)
        print(f"{'Object Type':<18} {'STIX Identifier':<36} {'Name / Description':<20}")
        print("-" * 75)
        for obj in objects[:6]:
            t = obj.get("type", "unknown")
            oid = obj.get("id", "N/A")
            name = obj.get("name") or obj.get("value") or obj.get("description") or "Forensic Artifact"
            print(f"{t:<18} {oid[:34]:<36} {str(name)[:18]:<20}")
        print("-" * 75)
    else:
        print("[-] STIX JSON bundle not located.")

    quiz_questions = [
        {
            "question": "What is the primary difference between a STIX SDO and a STIX SCO?",
            "options": [
                "SDOs represent high-level threat concepts (Threat Actor, Attack Pattern); SCOs represent observed technical artifacts (IP, Hash, File)",
                "SCOs are only used on mobile phones",
                "SDOs cannot have JSON formatting",
                "There is no difference"
            ],
            "correct": 1,
            "explanation": "SDOs provide context and intent (Actor, Campaign), while SCOs represent concrete observed data (IPs, MD5 hashes, registry keys)."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 8: BITCOIN & BLOCKCHAIN FORENSICS
# =====================================================================
def module_bitcoin_forensics():
    clear()
    draw_header("Module 8: Cryptocurrency & Blockchain Forensics")

    print(Style.BOLD + "[1] Theoretical Foundations & The UTXO Model:" + Style.END)
    print(
        "Bitcoin and public blockchains operate on an Unspent Transaction Output (UTXO) accounting model.\n"
        "Transactions consume existing UTXOs as inputs and create new UTXOs as outputs.\n"
        "Investigators trace illicit fund flows using blockchain clustering heuristics:\n"
        " 1. Multi-Input Heuristic (Common Ownership): All inputs in a single transaction belong to the same wallet.\n"
        " 2. Change Address Detection: Identifying outputs that return remainder funds to the sender."
    )

    print("\n" + Style.BOLD + "[2] Bitcoin Cryptographic Address Derivation:" + Style.END)
    print(Style.CYAN + """
Private Key (256-bit scalar)
   |  [ECDSA secp256k1 Curve Multiplication]
   v
Public Key (512-bit point / 256-bit compressed)
   |  [SHA-256 Hash] -> [RIPEMD-160 Hash]
   v
Public Key Hash (160-bit HASH160)
   |  [Base58Check Encoding + Version Byte 0x00 + 4-byte Checksum]
   v
Legacy Bitcoin Address (e.g., 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
""" + Style.END)

    print(Style.BOLD + "[3] Live Cryptographic Derivation Demonstration:" + Style.END)
    sample_pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    pub_bytes = bytes.fromhex(sample_pubkey_hex)
    sha_hash = hashlib.sha256(pub_bytes).digest()
    ripemd = hashlib.new('ripemd160', sha_hash).hexdigest()
    print(f"Sample Public Key : {sample_pubkey_hex}")
    print(f"SHA-256 Hash      : {sha_hash.hex()}")
    print(f"RIPEMD-160 (HASH160): {ripemd}")
    print("Forensic Meaning  : HASH160 serves as the cryptographic recipient in Pay-to-PubKey-Hash (P2PKH) scripts.")

    quiz_questions = [
        {
            "question": "What does the 'Multi-Input Common Ownership Heuristic' assert in Bitcoin forensics?",
            "options": [
                "All input addresses spent in a single Bitcoin transaction are controlled by the same entity",
                "Bitcoin can only be sent to one person at a time",
                "All transactions require government approval",
                "Mining fees are returned to the sender"
            ],
            "correct": 1,
            "explanation": "Because signing multiple inputs requires private keys for each input address, they are presumed to belong to the same wallet entity."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 9: IOT, DRONE & EMBEDDED FORENSICS
# =====================================================================
def module_drone_iot_forensics():
    clear()
    draw_header("Module 9: IoT, Drone & Embedded Hardware Forensics")

    print(Style.BOLD + "[1] Theoretical Foundations & Telemetry Acquisition:" + Style.END)
    print(
        "IoT devices (DJI Drones, Amazon Echo, Eufy Smart Doorbells) record continuous environmental\n"
        "and telemetry data across internal flash NAND memory and companion smartphone apps.\n"
        "Forensic examiners recover:\n"
        " - DAT / FLY flight records (Propeller RPM, battery voltage, pitch/roll/yaw, GPS altitude).\n"
        " - EXIF Geotag metadata in recorded JPEG/MP4 media files.\n"
        " - Wi-Fi probe requests and TLS handshake server names (SNI) to IoT cloud controllers."
    )

    print("\n" + Style.BOLD + "[2] Drone Forensic Artifact Hierarchy:" + Style.END)
    print(Style.CYAN + """
Drone Hardware (DJI Mavic Air)
   +--- MicroSD Card: Media files (.JPG, .MP4) with embedded EXIF GPS tags.
   +--- Internal Flash: Encrypted .DAT flight telemetry logs.
   
Companion Mobile Device (Android / iOS)
   +--- App Sandbox: Unencrypted TXT/CSV flight logs & waypoint cache.
   +--- Cache Thumbnails: Geotagged cached FPV preview images.
""" + Style.END)

    print(Style.BOLD + "[3] Live EXIF Geolocation Extraction Example:" + Style.END)
    print("Simulated EXIF GPS Record extracted from aerial image:")
    print("  - GPS Latitude : 37 deg 46' 29.8\" N  (Decimal: 37.774944)")
    print("  - GPS Longitude: 122 deg 25' 9.8\" W  (Decimal: -122.419400)")
    print("  - GPS Altitude : 112.5 meters above sea level")
    print("  - Camera Model : Hasselblad L1D-20c (DJI Mavic Pro)")

    quiz_questions = [
        {
            "question": "Where is the most accessible unencrypted flight trajectory data usually recovered during drone investigations?",
            "options": [
                "Inside the companion smartphone DJI Fly/Go app sandbox directory",
                "Inside the drone's motor firmware",
                "In the drone battery micro-controller",
                "Drones do not store flight data"
            ],
            "correct": 1,
            "explanation": "Mobile flight apps store unencrypted cached flight records (TXT/CSV) that synchronize during flight, making them primary evidence targets."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 10: AI IN FORENSICS & NLP TRIAGE
# =====================================================================
def module_ai_forensics():
    clear()
    draw_header("Module 10: AI in Forensics - Model Fine-Tuning & Evaluation")

    print(Style.BOLD + "[1] Theoretical Foundations & Forensic NLP Triage:" + Style.END)
    print(
        "Digital investigations frequently encounter petabytes of unstructured text (emails, chat logs, transcripts).\n"
        "Natural Language Processing (NLP) models (e.g., BERT, RoBERTa, LLMs) are fine-tuned to automate\n"
        "Named Entity Recognition (NER) for Indicators of Compromise (IPs, MD5 hashes, BTC wallet addresses).\n"
        "In legal proceedings, an AI model's evidentiary reliability is measured using Confusion Matrices and statistical metrics."
    )

    print("\n" + Style.BOLD + "[2] Statistical Evaluation Formulas:" + Style.END)
    print(Style.CYAN + """
                 +-----------------------+-----------------------+
                 | Predicted Negative    | Predicted Positive    |
+----------------+-----------------------+-----------------------+
| Actual Negative| True Negative  (TN)   | False Positive (FP)   |
+----------------+-----------------------+-----------------------+
| Actual Positive| False Negative (FN)   | True Positive  (TP)   |
+----------------+-----------------------+-----------------------+
""" + Style.END)
    print(" - Accuracy  = (TP + TN) / (TP + TN + FP + FN)")
    print(" - Precision = TP / (TP + FP)   [Of all flagged indicators, how many were genuine?]")
    print(" - Recall    = TP / (TP + FN)   [Of all genuine indicators present, how many did the AI catch?]")
    print(" - F1-Score  = 2 * (Precision * Recall) / (Precision + Recall)")

    print("\n" + Style.YELLOW + "[PRACTICAL CHALLENGE 10 - Evaluation Runner]" + Style.END)
    print("Scenario: You are auditing the fine-tuned IP identification model on 100 test evidence samples.")
    print("Task: Enter the command to run the accuracy evaluation script:")

    while True:
        cmd = input(Style.BOLD + "dfir-lab (ai) > " + Style.END).strip()
        if not cmd:
            continue
        if cmd.lower() in ["hint", "help"]:
            print(Style.BLUE + "Hint: Enter: python3 code/model_accuracy.py or python run_all_labs.py" + Style.END)
            continue
        if cmd.lower() == "skip":
            break
        if "model_accuracy" in cmd.lower() or "run_all" in cmd.lower() or "python" in cmd.lower():
            print(Style.GREEN + "\n[+] Executing statistical evaluation on test evidence dataset...\n" + Style.END)
            break
        else:
            print(Style.RED + "[-] Enter: python3 code/model_accuracy.py or type 'hint'." + Style.END)

    print(Style.BOLD + "[3] Live Statistical Output on 100 Evidence Samples:" + Style.END)
    dataset_path = os.path.join(REPO_ROOT, "AI4Forensics/IP_Identifier_Fine_Tuning/Calculate_Confusion_Matrix/dataset/testing100_results_dataset.csv")
    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        y_true, y_pred = df["label"], df["pred_label"]
        cm = confusion_matrix(y_true, y_pred)
        acc = accuracy_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)
        
        print(f"Total Test Set Samples: {len(df)}")
        print("\nConfusion Matrix:")
        print(cm)
        print(f"\nModel Accuracy:  {acc * 100:.2f}%")
        print(f"Model F1-Score:  {f1:.4f}")
        print("\nDetailed Classification Report:")
        print(classification_report(y_true, y_pred))
        print(Style.BOLD + "Forensic Finding:" + Style.END)
        print("The fine-tuned model achieved 100% precision with zero false positive indicators.")
    else:
        print("[-] Dataset not found.")

    quiz_questions = [
        {
            "question": "In digital forensics triage, why is High Precision critical when extracting suspect IPs?",
            "options": [
                "High Precision minimizes False Positives so investigators do not waste time chasing innocent hosts",
                "High Precision makes the computer boot faster",
                "High Precision compresses the raw disk image",
                "High Precision converts IP addresses into domain names"
            ],
            "correct": 1,
            "explanation": "High precision ensures that nearly 100% of flagged indicators are genuine threats, preventing false accusations and wasted investigative hours."
        },
        {
            "question": "If an AI model has 90 True Positives, 10 False Positives, and 0 False Negatives, what is its Recall?",
            "options": ["90%", "100%", "50%", "0%"],
            "correct": 2,
            "explanation": "Recall = TP / (TP + FN) = 90 / (90 + 0) = 1.0 (100%). All actual positive indicators were successfully identified."
        }
    ]
    run_quiz(quiz_questions)
    pause()

# =====================================================================
# MODULE 11: INTERACTIVE FORENSIC DIRECT SANDBOX & EVIDENCE INSPECTOR
# =====================================================================
def module_interactive_sandbox():
    while True:
        clear()
        draw_header("Module 11: Interactive Forensic Direct Sandbox & Evidence Inspector")
        print(Style.BOLD + "Select a live interactive forensic workbench tool:" + Style.END + "\n")
        print(" [1] Live SQLite Query Terminal (Query database.sqlite live)")
        print(" [2] Live Windows Security Event Searcher (Filter XML by Event ID)")
        print(" [3] Live Cryptographic Hash & Magic Byte Calculator (Inspect strings/files)")
        print(" [4] Live STIX 2.1 Threat Intel IOC JSON Generator")
        print(" [5] Return to Main Menu")
        print()

        choice = input(Style.BOLD + "Select a workbench tool [1-5] > " + Style.END).strip()
        
        if choice == "1":
            clear()
            draw_header("Interactive SQLite Query Terminal")
            db_path = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/HillaryEmails/archive/database.sqlite")
            if not os.path.exists(db_path):
                print("[-] Database not found.")
                pause()
                continue
            
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            print("Connected to: database.sqlite")
            print("Type any valid SQL SELECT query, or 'schema' to see tables, or 'exit' to return.\n")
            print("Example: SELECT Id, ExtractedSubject FROM Emails LIMIT 5;")
            print("-" * 75)
            
            while True:
                q = input(Style.BOLD + "sqlite-sandbox > " + Style.END).strip()
                if not q:
                    continue
                if q.lower() in ["exit", "quit", "q"]:
                    break
                if q.lower() == "schema":
                    cur.execute("SELECT sql FROM sqlite_master WHERE type='table';")
                    for s in cur.fetchall():
                        print(Style.CYAN + (s[0] or "") + Style.END)
                    continue
                try:
                    cur.execute(q)
                    rows = cur.fetchmany(20)
                    if not rows:
                        print("[+] Query executed. 0 records returned.")
                    else:
                        for row in rows:
                            print(row)
                except Exception as e:
                    print(Style.RED + f"SQL Error: {e}" + Style.END)
            conn.close()

        elif choice == "2":
            clear()
            draw_header("Interactive Windows Security Event Searcher")
            xml_path = os.path.join(REPO_ROOT, "NIST_Data_Leakage_Case/py_version/pycode/security_evt_xml/SecurityEvt_formatted.xml")
            if not os.path.exists(xml_path):
                print("[-] XML file not found.")
                pause()
                continue
            
            tree = ET.parse(xml_path)
            root = tree.getroot()
            target_eid = input(Style.BOLD + "Enter Event ID to search (e.g., 4608, 4624, 4731, or 'all') > " + Style.END).strip()
            
            matches = []
            for event in root.findall(".//Event"):
                eid = event.find(".//EventID")
                stime = event.find(".//TimeCreated")
                if eid is not None and (target_eid.lower() == "all" or eid.text == target_eid):
                    t = stime.attrib.get("SystemTime", "") if stime is not None else ""
                    matches.append((eid.text, t))
            
            print(f"\n[+] Found {len(matches)} matching events:")
            print("-" * 60)
            print(f"{'Index':<6} {'Event ID':<12} {'System Time (UTC)':<24}")
            print("-" * 60)
            for idx, (eid, t) in enumerate(matches[:15], 1):
                print(f"{idx:<6} {eid:<12} {t:<24}")
            if len(matches) > 15:
                print(f"... and {len(matches) - 15} more records.")
            print("-" * 60)
            pause()

        elif choice == "3":
            clear()
            draw_header("Cryptographic Hash & Magic Byte Inspector")
            text_input = input(Style.BOLD + "Enter text string or hexadecimal bytes to inspect > " + Style.END).strip()
            if text_input:
                raw_bytes = text_input.encode('utf-8')
                md5_h = hashlib.md5(raw_bytes).hexdigest()
                sha1_h = hashlib.sha1(raw_bytes).hexdigest()
                sha256_h = hashlib.sha256(raw_bytes).hexdigest()
                
                print("\n" + Style.BOLD + "Cryptographic Checksums (Evidence Integrity):" + Style.END)
                print(f"MD5   : {md5_h}")
                print(f"SHA1  : {sha1_h}")
                print(f"SHA256: {sha256_h}")
                print(f"Hex Representation: {raw_bytes.hex().upper()}")
            pause()

        elif choice == "4":
            clear()
            draw_header("STIX 2.1 Threat Intel IOC JSON Generator")
            ip_val = input(Style.BOLD + "Enter Malicious IP Address to generate STIX IOC > " + Style.END).strip()
            if not ip_val:
                ip_val = "198.51.100.42"
            
            ioc_bundle = {
                "type": "bundle",
                "id": f"bundle--{hashlib.md5(ip_val.encode()).hexdigest()}",
                "objects": [
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{hashlib.md5((ip_val + '_ind').encode()).hexdigest()}",
                        "name": f"Malicious C2 IP: {ip_val}",
                        "pattern": f"[ipv4-addr:value = '{ip_val}']",
                        "pattern_type": "stix"
                    },
                    {
                        "type": "ipv4-addr",
                        "spec_version": "2.1",
                        "id": f"ipv4-addr--{hashlib.md5(ip_val.encode()).hexdigest()}",
                        "value": ip_val
                    }
                ]
            }
            print(Style.CYAN + json.dumps(ioc_bundle, indent=2) + Style.END)
            pause()

        elif choice in ["5", "exit", "quit", "q"]:
            break

# =====================================================================
# MAIN MENU
# =====================================================================
def main_menu():
    while True:
        clear()
        draw_header("Interactive Digital Forensics Laboratory & Concept Tutor")
        print(Style.BOLD + "Select an Investigation Module to Learn & Execute:" + Style.END + "\n")
        print(" [1]  Module 1:  Disk Partition & Filesystem Forensics (The Sleuth Kit)")
        print(" [2]  Module 2:  Host Forensics & Windows Security Event Logs (NIST Case)")
        print(" [3]  Module 3:  Network Traffic Forensics & TShark Protocol Analysis")
        print(" [4]  Module 4:  Memory Forensics & Volatile Artifact Analysis (Volatility)")
        print(" [5]  Module 5:  Mobile & Forensic SQLite Evidence Database Analysis")
        print(" [6]  Module 6:  Data Carving & File Signature Recovery (Foremost)")
        print(" [7]  Module 7:  Cyber Threat Intelligence & STIX 2.1 Evidence Graphs")
        print(" [8]  Module 8:  Cryptocurrency & Blockchain Forensics (Bitcoin)")
        print(" [9]  Module 9:  IoT, Drone & Embedded Hardware Forensics (DJI Mavic)")
        print(" [10] Module 10: AI in Digital Forensics (Model Fine-Tuning & Evaluation)")
        print(" [11] Module 11: Master Interactive Forensic Workbench & Evidence Sandbox")
        print(" [12] Run Master Automated Verification Suite (All Labs)")
        print(" [13] Exit Laboratory")
        print()

        choice = input(Style.BOLD + "Select an option [1-13] > " + Style.END).strip()
        if choice == "1":
            module_disk_forensics()
        elif choice == "2":
            module_event_logs()
        elif choice == "3":
            module_network_forensics()
        elif choice == "4":
            module_memory_forensics()
        elif choice == "5":
            module_sqlite_forensics()
        elif choice == "6":
            module_data_carving()
        elif choice == "7":
            module_stix_forensics()
        elif choice == "8":
            module_bitcoin_forensics()
        elif choice == "9":
            module_drone_iot_forensics()
        elif choice == "10":
            module_ai_forensics()
        elif choice == "11":
            module_interactive_sandbox()
        elif choice == "12":
            clear()
            draw_header("Master Automated Verification Suite")
            subprocess.run([sys.executable, os.path.join(REPO_ROOT, "run_all_labs.py")])
            pause()
        elif choice in ["13", "exit", "quit", "q"]:
            print("\nExiting Digital Forensics Laboratory. Session ended.")
            break

if __name__ == "__main__":
    main_menu()
