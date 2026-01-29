from modules.encoder import Encoder
from modules.obfuscator import Obfuscator
from modules.evasion_test import EvasionTester

def main():
    print("=== Custom Payload Encoder & Decoder Framework ===")
    
    # STEP 1: Choose Mode
    print("\n--- Select Mode ---")
    print("1. Encode (Transform Payload)")
    print("2. Decode (Restore Payload)")
    mode = input("Mode: ")

    # STEP 2: Input Payload
    prompt_text = "Enter raw payload: " if mode == '1' else "Enter encoded string: "
    raw_payload = input(f"\n{prompt_text}")

    # STEP 3: Method Selection
    print("\n--- Select Method ---")
    print("1. Base64")
    print("2. ROT13")
    print("3. XOR")
    
    # Obfuscation is usually one-way, so we disable it for decoding
    if mode == '1':
        print("4. String Splitting (Obfuscation - Encode Only)")
    
    choice = input("Choice: ")

    encoder = Encoder(raw_payload)
    result_payload = ""

    # LOGIC HANDLER
    if choice == '1': # Base64
        if mode == '1':
            result_payload = encoder.to_base64()
        else:
            result_payload = encoder.from_base64()

    elif choice == '2': # ROT13
        if mode == '1':
            result_payload = encoder.to_rot13()
        else:
            result_payload = encoder.from_rot13()

    elif choice == '3': # XOR
        key = input("Enter XOR Key: ")
        if mode == '1':
            result_payload = encoder.xor_encrypt(key)
        else:
            result_payload = encoder.xor_decrypt(key)

    elif choice == '4' and mode == '1': # Obfuscation
        obfuscator = Obfuscator(raw_payload)
        result_payload = obfuscator.split_string()

    else:
        print("Invalid selection or method not available in this mode.")
        return

    # STEP 4: Output & Testing
    print("\n" + "="*30)
    if mode == '1':
        print(f"Original:    {raw_payload}")
        print(f"ENCODED:     {result_payload}")
        
        # Test evasion only when encoding
        tester = EvasionTester()
        print(f"Detection:   {tester.scan(result_payload)}")
    else:
        print(f"Input:       {raw_payload}")
        print(f"DECODED:     {result_payload}")
    print("="*30 + "\n")

if __name__ == "__main__":
    main()