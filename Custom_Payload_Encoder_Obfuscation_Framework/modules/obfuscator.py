import random
import string

class Obfuscator:
    def __init__(self, payload):
        self.payload = payload

    # --- EXISTING METHODS ---
    def insert_random_chars(self):
        obfuscated = ""
        for char in self.payload:
            obfuscated += char + random.choice(['#', '%', '?', '!']) 
        return obfuscated

    def split_string(self):
        return "+".join([f'"{char}"' for char in self.payload])

    def reverse_string(self):
        return self.payload[::-1]

    def escape_sequence(self):
        return "".join([f"\\x{ord(char):02x}" for char in self.payload])

    # --- NEW: MISSING FEATURES IMPLEMENTED ---

    def polymorphic_junk(self):
        """
        Simulates Polymorphism by adding random junk code/comments.
        This ensures the file hash (signature) changes every time.
        """
        junk_start = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        junk_end = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        # Add comments specific to scripting languages (works for Python/Powershell/Bash)
        return f"# Random_Sig: {junk_start}\n{self.payload}\n# End_Sig: {junk_end}"

    def command_substitution(self):
        """
        Simulates Code Substitution by swapping standard commands 
        with equivalent short-hand aliases.
        """
        # Dictionary of common command replacements
        subs = {
            "Invoke-Expression": "IEX",
            "Invoke-WebRequest": "iwr",
            "Write-Host": "echo",
            "Get-Content": "cat",
            "Stop-Process": "kill",
            "Clear-Host": "cls",
            "system": "exec"
        }
        
        result = self.payload
        for original, alias in subs.items():
            # Case-insensitive replacement
            if original.lower() in result.lower():
                result = result.replace(original, alias)
                result = result.replace(original.lower(), alias)
        
        return result