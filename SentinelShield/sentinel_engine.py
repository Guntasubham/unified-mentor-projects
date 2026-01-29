import re
import logging
import time
import datetime
from collections import defaultdict

# --- CONFIGURATION & LOGGING ---
logging.basicConfig(
    filename='sentinel_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SentinelEngine:
    def __init__(self):
        # 1. ATTACK SIGNATURES (Regex Rules)
        self.signatures = {
            "SQL_INJECTION": r"(union\s+select|or\s+1=1|--|#|/\*|\*/|';)",
            "XSS": r"(<script>|javascript:|onerror=|onload=|alert\(|document\.cookie)",
            "PATH_TRAVERSAL": r"(\.\./|\.\.\\|/etc/passwd|c:\\windows|boot\.ini)",
            "COMMAND_INJECTION": r"(;\s*|\|\s*|&&\s*)(cat|ls|pwd|whoami|wget|curl|ping)"
        }
        
        # 2. HONEYPOTS (Deception Technology)
        # These are fake hidden URLs. If anyone touches them, it's definitely an attack.
        self.honeypots = ["/admin-backup", "/db-config.php", "/shadow-file"]
        
        # 3. RATE LIMITING CONFIGURATION
        self.ip_traffic = defaultdict(list)
        self.RATE_LIMIT_THRESHOLD = 5  # Max requests allowed
        self.RATE_LIMIT_WINDOW = 10    # Time window in seconds

        # 4. STATISTICS TRACKING
        self.stats = {
            "total_requests": 0,
            "blocked": 0,
            "allowed": 0,
            "sql_attempts": 0,
            "xss_attempts": 0,
            "honeypot_hits": 0
        }

    def check_rate_limit(self, ip):
        """Checks if an IP is sending requests too fast."""
        current_time = time.time()
        self.ip_traffic[ip] = [t for t in self.ip_traffic[ip] if current_time - t < self.RATE_LIMIT_WINDOW]
        
        if len(self.ip_traffic[ip]) >= self.RATE_LIMIT_THRESHOLD:
            return True
        
        self.ip_traffic[ip].append(current_time)
        return False

    def inspect_request(self, ip, payload):
        """Main logic to inspect HTTP request components."""
        self.stats["total_requests"] += 1

        # A. CHECK HONEYPOTS (Highest Priority)
        # Checks if the payload contains any of our trap URLs
        if any(trap in payload for trap in self.honeypots):
            self.stats["blocked"] += 1
            self.stats["honeypot_hits"] += 1
            log_msg = f"CRITICAL [Honeypot Triggered]: IP {ip} accessed trap URL inside '{payload}'"
            logging.critical(log_msg)
            return "BLOCKED", "Honeypot Violation", log_msg

        # B. CHECK RATE LIMIT
        if self.check_rate_limit(ip):
            self.stats["blocked"] += 1
            log_msg = f"BLOCKED [Rate Limit]: Too many requests from {ip}"
            logging.warning(log_msg)
            return "BLOCKED", "Rate Limit Exceeded", log_msg

        # C. CHECK SIGNATURES
        for attack_type, pattern in self.signatures.items():
            if re.search(pattern, payload, re.IGNORECASE):
                self.stats["blocked"] += 1
                if attack_type == "SQL_INJECTION": self.stats["sql_attempts"] += 1
                if attack_type == "XSS": self.stats["xss_attempts"] += 1
                
                log_msg = f"BLOCKED [{attack_type}]: Pattern found in payload from {ip}"
                logging.warning(f"{log_msg} | Payload: {payload}")
                return "BLOCKED", attack_type, log_msg

        # D. ALLOW REQUEST
        self.stats["allowed"] += 1
        log_msg = f"ALLOWED: Safe request from {ip}"
        logging.info(f"{log_msg} | Payload: {payload}")
        return "ALLOWED", "Normal", log_msg