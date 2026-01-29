import re

class EvasionTester:
    def __init__(self):
        # SIMULATED YARA RULES (Regex patterns)
        # These mimic how real YARA rules detect patterns in malware
        self.rules = {
            "Suspicious_Shell": r"(powershell|cmd\.exe|/bin/sh|/bin/bash)",
            "Network_Tool": r"(wget|curl|Invoke-WebRequest|http://|https://)",
            "Execution_Function": r"(exec|eval|system|popen|spawn|CreateProcess)",
            "Obfuscation_Base64": r"(Base64|FromBase64String|::FromBase64)",
            "Obfuscation_Hex": r"\\x[0-9a-fA-F]{2}", 
            "Keylogger_Pattern": r"(GetAsyncKeyState|SetWindowsHookEx|GetForegroundWindow)",
            "Ransomware_Pattern": r"(CryptEncrypt|vssadmin|delete shadow|wbadmin)"
        }

    def scan(self, payload):
        """Scans a text string (used in the Payload Tool)."""
        detections = []
        for rule_name, pattern in self.rules.items():
            if re.search(pattern, payload, re.IGNORECASE):
                detections.append(rule_name)
        
        if detections:
            return (True, f"DETECTED ❌ (Matched: {', '.join(detections)})")
        return (False, "BYPASSED ✅ (No matching rules found)")

    def scan_file(self, file_path):
        """[NEW] Scans a binary file path (used in Binary Analysis)."""
        try:
            with open(file_path, "rb") as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            detections = []
            for rule_name, pattern in self.rules.items():
                if re.search(pattern, content, re.IGNORECASE):
                    detections.append(rule_name)
            
            return detections
        except Exception as e:
            return [f"Error scanning file: {str(e)}"]