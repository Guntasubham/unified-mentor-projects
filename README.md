# Unified Mentor Projects

This repository contains my cybersecurity projects completed during the Unified Mentor internship. Each folder represents a distinct tool focusing on different aspects of offensive and defensive security, ranging from payload evasion to intrusion detection.

## 📂 Project Structure

### 1. Custom Payload Encoder & Obfuscation Framework (CPEOF)
* [cite_start]**Description:** A GUI-based framework designed to study evasion techniques[cite: 5]. [cite_start]It encodes (Base64, ROT13, XOR) and obfuscates payload strings to simulate how malware bypasses signature-based detection systems like AV and EDR[cite: 21, 23].
* **Tech Stack:** Python, Tkinter, PyInstaller, Base64.
* [cite_start]**Key Learning:** Understanding static analysis limitations and Red Team evasion workflows[cite: 55].

### 2. Password Cracking & Credential Attack Suite
* [cite_start]**Description:** A security auditing toolkit that generates custom dictionaries, extracts hashes from Linux/Windows files, and simulates brute-force attacks to test password strength[cite: 103]. [cite_start]It calculates password entropy to identify weak credentials[cite: 132].
* **Tech Stack:** Python, hashlib, itertools, Tkinter.
* [cite_start]**Key Learning:** Secure credential storage (Salting/Hashing) and authentication policy enforcement[cite: 162].

### 3. SentinelShield (IDS & WAF)
* [cite_start]**Description:** An Advanced Intrusion Detection System and Web Application Firewall[cite: 203]. [cite_start]It intercepts HTTP traffic to detect SQL Injection and XSS attacks using Regex signatures and includes a "Honeypot" module to trap attackers[cite: 208, 218].
* **Tech Stack:** Python, Regex (re), Tkinter (Dashboard).
* [cite_start]**Key Learning:** Web attack signatures (SQLi/XSS) and SOC monitoring operations[cite: 260].

### 4. Windows Service Process Monitoring Agent (HIDS)
* [cite_start]**Description:** A host-based intrusion detection system (HIDS) that monitors Windows endpoints in real-time[cite: 275]. [cite_start]It detects suspicious behavior such as persistence mechanisms in the Registry, process injection, and execution from volatile directories like %TEMP%[cite: 276, 297].
* **Tech Stack:** Python, psutil, winreg, ctypes.
* [cite_start]**Key Learning:** Windows API internals, behavioral analysis, and malware persistence techniques[cite: 345].

## 🚀 How to Run
To run any of these projects, navigate to the specific project folder and run the main Python file (usually `main.py` or the GUI script).

Example:
```bash
# Navigate to the project folder
cd "Project-Name-Folder"

# Run the application
python main_gui.py

Author
Gunta Subham
B.Tech in Computer Science
Domain: Cybersecurity