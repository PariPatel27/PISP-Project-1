from secure_messaging import SecureMessaging, print_section, bytes_to_hex
from datetime import datetime
import os


def main():
    print("\n" + "="*70)
    print("BOB'S TERMINAL - SECURE MESSAGE RECEIVING")
    print("Task 5: Authenticated Decryption (Encrypt-then-MAC)")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    sm = SecureMessaging()
    
    print_section("STEP 1: READ ALICE'S MESSAGE")
    
    filename = "alice_message.txt"
    
    print(f"\n Looking for: {filename}")
    
    while not os.path.exists(filename):
        input(f" File not found. Run alice_send.py first, then press Enter...")
    
    print(f" File found! Reading Alice's secure message...")
    
    with open(filename, 'r') as f:
        content = f.read()
    
    # Parse the file
    try:
        mode = content.split("ENCRYPTION_MODE:\n")[1].split("\n\n")[0].strip()
        iv_hex = content.split("IV:\n")[1].split("\n\n")[0].strip()
        ciphertext_hex = content.split("CIPHERTEXT:\n")[1].split("\n\n")[0].strip()
        hmac_hex = content.split("HMAC:\n")[1].split("\n\n")[0].strip()
        combined_hex = content.split("COMBINED:\n")[1].split("\n\n")[0].strip()
        encryption_key_hex = content.split("ENCRYPTION_KEY:\n")[1].split("\n\n")[0].strip()
        hmac_key_hex = content.split("HMAC_KEY:\n")[1].strip()
        
        # Convert from hex
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        received_hmac = bytes.fromhex(hmac_hex)
        combined_data = bytes.fromhex(combined_hex)
        encryption_key = bytes.fromhex(encryption_key_hex)
        hmac_key = bytes.fromhex(hmac_key_hex)
        
        print(f"\n Data parsed successfully!")
        print(f"  Mode: AES-{mode}")
        print(f"  IV: {len(iv)} bytes")
        print(f"  Ciphertext: {len(ciphertext)} bytes")
        print(f"  HMAC: {len(received_hmac)} bytes")
        print(f"  Combined: {len(combined_data)} bytes")
        
    except Exception as e:
        print(f"\n ERROR parsing file: {e}")
        return
    
    input("\n[Press Enter to continue...]")
    
    print_section("STEP 2: RECEIVED DATA FROM ALICE")
    
    print(f"\n{'='*70}")
    print("RECEIVED CIPHERTEXT:")
    print(f"{'='*70}")
    print(f"Hex: {bytes_to_hex(ciphertext)}")
    print(f"Length: {len(ciphertext)} bytes")
    
    print(f"\n{'='*70}")
    print("RECEIVED HMAC:")
    print(f"{'='*70}")
    print(f"Hex: {received_hmac.hex()}")
    print(f"Length: {len(received_hmac)} bytes")
    
    print(f"\n{'='*70}")
    print("ENCRYPTION PARAMETERS:")
    print(f"{'='*70}")
    print(f"Mode: AES-{mode}")
    print(f"IV (hex): {iv.hex()}")
    print(f"Key (hex): {bytes_to_hex(encryption_key)}")
    
    input("\n[Press Enter to verify and decrypt...]")
    
    print_section("STEP 3: VERIFY MESSAGE INTEGRITY")
    
    print("\n Bob computing HMAC on received ciphertext...")
    print(f"\nINPUTS TO HMAC:")
    print(f"  Message (ciphertext): {bytes_to_hex(ciphertext)}")
    print(f"  HMAC Key: {bytes_to_hex(hmac_key)}")
    
    computed_hmac = sm.compute_hmac(ciphertext, hmac_key)
    
    print(f"\n{'='*70}")
    print("HMAC COMPARISON:")
    print(f"{'='*70}")
    print(f"Received HMAC:  {received_hmac.hex()}")
    print(f"Computed HMAC:  {computed_hmac.hex()}")
    
    # Verify
    print(f"\n Verifying HMAC...")
    is_valid = sm.verify_hmac(ciphertext, hmac_key, received_hmac)
    
    print(f"\n{'='*70}")
    if is_valid:
        print(" HMAC VERIFICATION: PASSED")
        print(" Message integrity confirmed!")
        print(" Message is authentic (from Alice)")
        print(" Message was not tampered!")
    else:
        print(" HMAC VERIFICATION: FAILED ")
        print(" Message may be tampered!")
        print(" Aborting decryption for security!")
        return
    print(f"{'='*70}")
    
    input("\n[Press Enter to decrypt...]")
    
    
    print_section("STEP 4: DECRYPT MESSAGE")
    
    print("\n Decrypting ciphertext...")
    print(f"\nINPUTS TO DECRYPTION:")
    print(f"  Ciphertext (hex): {bytes_to_hex(ciphertext)}")
    print(f"  Key (hex): {bytes_to_hex(encryption_key)}")
    print(f"  IV (hex): {iv.hex()}")
    print(f"  Mode: AES-{mode}")
    
    decrypted_message = sm.sym_dec(ciphertext, encryption_key, iv, mode)
    
    print(f"\n{'='*70}")
    print("DECRYPTED MESSAGE:")
    print(f"{'='*70}")
    print(f'"{decrypted_message}"')
    print(f"{'='*70}")
    

    print_section("STEP 5: AUTHENTICATED DECRYPTION (Complete)")
    
    print("\n Using authenticated_decrypt function...")
    print("(This does both HMAC verification and decryption)")
    
    final_message = sm.authenticated_decrypt(
        combined_data=combined_data,
        encryption_key=encryption_key,
        hmac_key=hmac_key,
        iv=iv,
        mode=mode
    )
    
    if final_message:
        print(f"\n{'='*70}")
        print("SUCCESSFULLY DECRYPTED MESSAGE:")
        print(f"{'='*70}")
        print(f'"{final_message}"')
        print(f"{'='*70}")
    
    print_section("BOB'S SESSION SUMMARY")
    
    print(f"""
SECURE MESSAGE RECEIVING COMPLETE!
{'='*70}

RECEIVED FROM ALICE:
  Ciphertext: {len(ciphertext)} bytes
  HMAC:       {len(received_hmac)} bytes
  Combined:   {len(combined_data)} bytes

VERIFICATION PROCESS:
  1. Received ciphertext from Alice
  2. Computed HMAC on received ciphertext
  3. Compared with Alice's HMAC -> {'MATCH ' if is_valid else 'MISMATCH '}
  4. Decrypted ciphertext -> Plaintext

DECRYPTED MESSAGE:
  "{decrypted_message if is_valid else 'N/A - HMAC failed'}"

SECURITY GUARANTEES:
  Confidentiality: Only Bob can decrypt (has the key)
   Integrity: HMAC ensures message not modified
   Authentication: HMAC proves message from Alice

 SECURE COMMUNICATION SUCCESSFUL 
    """)
    
    print("="*70)
    print(f"Session completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Program interrupted.")
