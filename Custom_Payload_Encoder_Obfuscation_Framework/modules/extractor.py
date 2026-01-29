import re

class StringExtractor:
    def extract_from_file(self, file_path, min_length=4):
        """
        Simulates PE/ELF string extraction.
        Reads a binary file and returns all printable strings > min_length.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Regex to find sequences of 4+ printable characters
            # This works on both Windows (PE) and Linux (ELF) binaries
            pattern = b"[ -~]{" + str(min_length).encode() + b",}"
            strings = re.findall(pattern, data)
            
            # Decode bytes to string
            decoded_strings = [s.decode("utf-8", errors="ignore") for s in strings]
            
            return "\n".join(decoded_strings)
        except Exception as e:
            return f"Error extracting strings: {str(e)}"