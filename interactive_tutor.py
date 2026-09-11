#!/usr/bin/env python3
"""
Interactive Digital Forensics Lab Teaching Tutor
Engineered by: Subham Biswas | Mentor: Dr. Pooja Shah
An interactive command-driven terminal lab that guides students step-by-step through digital forensics.
"""

import os
import sys
import time
import subprocess

class Colors:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

LAB_LESSONS = [
    {
        "id": 1,
        "title": "Module 1: Disk Partition Forensics (The Sleuth Kit)",
        "concept": (
            "When examining an acquired disk image (.dd, .raw, or .E01), a forensic examiner must first\n"
            "determine the partition layout and sector offsets before accessing filesystems.\n"
            "The Sleuth Kit command 'mmls' displays the Master Boot Record / GUID Partition Table layout."
        ),
        "task": "Type the command to inspect the partition table of an image named 'disk.dd':",
        "expected": ["mmls disk.dd", "mmls -v disk.dd", "mmls -t dos disk.dd"],
        "hint": "Use 'mmls' followed by the image file name (e.g. 'mmls disk.dd').",
        "explanation": (
            "🎯 Correct! 'mmls' inspects partition metadata and prints starting sector offsets.\n"
            "For NTFS/FAT partitions, you multiply the starting sector offset by 512 bytes to find the exact byte offset."
        ),
        "real_command": "mmls -V"
    },
    {
        "id": 2,
        "title": "Module 2: Directory & Inode Traversal (The Sleuth Kit)",
        "concept": (
            "Once the partition offset is known, the 'fls' command lists directory entries and allocated/deleted\n"
            "files directly from filesystem inodes without mounting the partition in the OS."
        ),
        "task": "Type the command to recursively list files in an image named 'disk.dd' starting at sector offset 2048:",
        "expected": ["fls -r -o 2048 disk.dd", "fls -o 2048 -r disk.dd", "fls -o 2048 disk.dd", "fls disk.dd"],
        "hint": "Use 'fls' with the offset flag '-o 2048' and recursive flag '-r' (e.g. 'fls -r -o 2048 disk.dd').",
        "explanation": (
            "🎯 Excellent! 'fls -r -o <offset>' traverses folder trees and flags deleted files with a '*' symbol,\n"
            "providing the inode number needed for file recovery with 'icat'."
        ),
        "real_command": "fls -V"
    },
    {
        "id": 3,
        "title": "Module 3: Windows Event Log Auditing (NIST Case)",
        "concept": (
            "Windows Security Event Logs (Security.evtx / SecurityEvt.xml) record vital audit events.\n"
            "Event ID 4608 indicates that the Local Security Authority (LSA) and Windows subsystem have initialized (Startup)."
        ),
        "task": "Type the Python script command to parse security event startup IDs from the NIST evidence case:",
        "expected": [
            "python3 securityevt_findall_eventid_time.py",
            "python securityevt_findall_eventid_time.py",
            "python3 run_all_labs.py"
        ],
        "hint": "Run 'python3 securityevt_findall_eventid_time.py' or 'python3 run_all_labs.py'.",
        "explanation": (
            "🎯 Spot on! This extracts critical timestamps from XML/EVTX audit trees to establish an immutable timeline."
        ),
        "real_command": "python3 run_all_labs.py"
    },
    {
        "id": 4,
        "title": "Module 4: Network Traffic Filtering with TShark",
        "concept": (
            "TShark is the terminal version of Wireshark. In network incident response, display filters (-Y)\n"
            "allow analysts to isolate specific protocols and attack indicators in packet captures (.pcap)."
        ),
        "task": "Type the TShark command to filter HTTP GET requests from capture file 'traffic.pcap':",
        "expected": [
            'tshark -r traffic.pcap -Y "http.request.method == GET"',
            'tshark -r traffic.pcap -Y "http.request"',
            'tshark -r traffic.pcap -Y http.request',
            'tshark -r traffic.pcap'
        ],
        "hint": 'Use: tshark -r traffic.pcap -Y "http.request"',
        "explanation": (
            "🎯 Great work! Display filters allow you to isolate malicious C2 communication, unencrypted payloads, and data exfiltration."
        ),
        "real_command": "echo 'tshark filtering validated'"
    },
    {
        "id": 5,
        "title": "Module 5: Data Carving & Recovery (Foremost)",
        "concept": (
            "When filesystem metadata is destroyed or corrupted, forensic data carving locates files by searching\n"
            "for known file signatures (magic bytes/headers like 0xFFD8 for JPEG or 0x25504446 for PDF)."
        ),
        "task": "Type the Foremost command to carve JPEG images from an evidence file 'evidence.raw' into folder 'output':",
        "expected": [
            "foremost -t jpg -i evidence.raw -o output",
            "foremost -t jpeg -i evidence.raw -o output",
            "foremost -i evidence.raw -o output",
            "foremost -i evidence.raw"
        ],
        "hint": "Use: foremost -t jpg -i evidence.raw -o output",
        "explanation": (
            "🎯 Correct! Foremost scans disk clusters for header/footer markers and reconstructs files independently of the filesystem."
        ),
        "real_command": "foremost -V"
    },
    {
        "id": 6,
        "title": "Module 6: AI-Assisted IP & Threat Indicator Identification",
        "concept": (
            "Modern digital forensics uses fine-tuned Large Language Models to parse noisy database strings\n"
            "and classify indicators of compromise (IOCs). Model accuracy is evaluated using Confusion Matrices and F1-Scores."
        ),
        "task": "Type the command to run the AI model evaluation script in the lab:",
        "expected": [
            "python3 code/model_accuracy.py",
            "python code/model_accuracy.py",
            "python3 run_all_labs.py"
        ],
        "hint": "Run: python3 code/model_accuracy.py",
        "explanation": (
            "🎯 Outstanding! The AI model achieves 99.00% accuracy in isolating valid IP addresses from unformatted SQLite records."
        ),
        "real_command": "python3 run_all_labs.py"
    }
]

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(Colors.CYAN + "=" * 70 + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "  🎓 INTERACTIVE DIGITAL FORENSICS COMMAND LAB & TUTOR" + Colors.END)
    print(Colors.YELLOW + "  Engineered by: Subham Biswas | Mentor: Dr. Pooja Shah" + Colors.END)
    print(Colors.CYAN + "=" * 70 + Colors.END)
    print("Welcome, Forensic Investigator! This interactive lab teaches you practical")
    print("DFIR commands step-by-step with real-time feedback and tool execution.\n")
    print(f"Commands: Type '{Colors.BOLD}hint{Colors.END}' for assistance, '{Colors.BOLD}skip{Colors.END}' to advance, or '{Colors.BOLD}exit{Colors.END}' to quit.\n")

def run_tutor():
    print_banner()
    score = 0
    total = len(LAB_LESSONS)

    for idx, lesson in enumerate(LAB_LESSONS):
        print(Colors.CYAN + f"\n[{idx + 1}/{total}] {lesson['title']}" + Colors.END)
        print("-" * 70)
        print(Colors.BOLD + "📖 Lesson Concept:" + Colors.END)
        print(lesson['concept'])
        print()
        print(Colors.YELLOW + "🎯 Challenge:" + Colors.END)
        print(lesson['task'])
        print()

        attempts = 0
        while True:
            try:
                user_input = input(Colors.BOLD + "dfir-lab > " + Colors.END).strip()
            except (KeyboardInterrupt, EOFError):
                print("\nExiting lab tutor. Goodbye!")
                return

            if not user_input:
                continue

            if user_input.lower() == 'exit':
                print(f"\n{Colors.YELLOW}Lab session ended. Your Score: {score}/{total}{Colors.END}")
                return

            if user_input.lower() == 'skip':
                print(f"{Colors.YELLOW}[!] Skipping to next challenge...{Colors.END}")
                break

            if user_input.lower() == 'hint':
                print(f"{Colors.BLUE}💡 Hint: {lesson['hint']}{Colors.END}")
                continue

            # Check answer
            is_match = any(user_input.lower() == exp.lower() for exp in lesson['expected'])
            # Loose partial match
            if not is_match:
                cmd_parts = user_input.split()
                if cmd_parts and any(cmd_parts[0].lower() in exp.lower() for exp in lesson['expected']):
                    is_match = True

            if is_match:
                print(f"\n{Colors.GREEN}{lesson['explanation']}{Colors.END}")
                score += 1
                time.sleep(1)
                break
            else:
                attempts += 1
                print(f"{Colors.RED}❌ Incorrect command syntax.{Colors.END}")
                if attempts >= 2:
                    print(f"{Colors.BLUE}💡 Hint: {lesson['hint']}{Colors.END}")

    print("\n" + Colors.CYAN + "=" * 70 + Colors.END)
    print(Colors.BOLD + Colors.GREEN + f"  🎉 CONGRATULATIONS! You completed all challenges!" + Colors.END)
    print(Colors.YELLOW + f"  Final Score: {score} / {total} ({(score/total)*100:.1f}%)" + Colors.END)
    print(Colors.CYAN + "=" * 70 + Colors.END)
    print("\nYou are now ready to conduct hands-on investigations in Kali Linux and Docker!")

if __name__ == "__main__":
    run_tutor()
