import base64
import codecs
import binascii

class Encoder:
    def __init__(self, payload):
        self.payload = payload

    # --- ENCODING METHODS ---
    def to_base64(self):
        # Base64 encoding
        encoded_bytes = base64.b64encode(self.payload.encode('utf-8'))
        return encoded_bytes.decode('utf-8')

    def to_rot13(self):
        # ROT13 substitution
        return codecs.encode(self.payload, 'rot_13')

    def xor_encrypt(self, key):
        # XOR encryption
        if not key: return self.payload
        encrypted = []
        for i in range(len(self.payload)):
            encrypted.append(chr(ord(self.payload[i]) ^ ord(key[i % len(key)])))
        return "".join(encrypted)

    # --- DECODING METHODS ---
    def from_base64(self):
        # Base64 decoding
        try:
            decoded_bytes = base64.b64decode(self.payload)
            return decoded_bytes.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return "Error: Invalid Base64 string"

    def from_rot13(self):
        # ROT13 is symmetric (applying it again decodes it)
        return codecs.encode(self.payload, 'rot_13')

    def xor_decrypt(self, key):
        # XOR is symmetric (applying it again with the same key decodes it)
        return self.xor_encrypt(key)