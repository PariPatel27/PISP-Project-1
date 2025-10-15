from secure_messaging import SecureMessaging, print_section, bytes_to_hex
from datetime import datetime
import os


def main():
    print("\n" + "="*70)
    print("ALICE'S TERMINAL - SECURE MESSAGE SENDING")
    print("Task 5: Authenticated Encryption (Encrypt-then-MAC)")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    sm = SecureMessaging()
    
    print_section("STEP 1: ENCRYPTION KEY")
    
    print("\nThis key should be derived from Task 3 (KDF output).")
    print("\nChoose encryption key source:")
    print("1. Enter key from Task 3 (hex format)")
    print("2. Use demo key")
    
    while True:
        key_choice = input("\nEnter choice (1 or 2): ").strip()
        if key_choice in ['1', '2']:
            break
        print(" Invalid!")
    
    if key_choice == '1':
        print("\n Enter encryption key from Task 3 (hex format):")
        print("(Should be 64 hex characters for 32-byte/256-bit key)")
        key_hex = input("Key (hex): ").strip()
        
        try:
            encryption_key = bytes.fromhex(key_hex)
            if len(encryption_key) not in [16, 24, 32]:
                print(f"  Key length {len(encryption_key)} bytes. Adjusting to 32 bytes...")
                encryption_key = (encryption_key * 2)[:32]
        except ValueError:
            print(" Invalid hex! Using demo key...")
            encryption_key = b'ThisIsA32ByteKeyForAESEncrypt!!'
    else:
        encryption_key = b'ThisIsA32ByteKeyForAESEncrypt!!'
        print(f" Using demo key")
    
    print(f"\n Encryption key: {bytes_to_hex(encryption_key)}")
    
    # Use same key for HMAC (in practice, should derive separate keys)
    hmac_key = encryption_key
    print(f"HMAC key: {bytes_to_hex(hmac_key)}")
    
    input("\n[Press Enter to continue...]")
    
    
    print_section("STEP 2: ENCRYPTION MODE")
    
    print("\nChoose encryption mode:")
    print("1. AES-CBC (Cipher Block Chaining)")
    print("2. AES-CTR (Counter Mode)")
    
    while True:
        mode_choice = input("\nEnter choice (1 or 2): ").strip()
        if mode_choice in ['1', '2']:
            break
        print(" Invalid!")
    
    mode = 'CBC' if mode_choice == '1' else 'CTR'
    print(f"\n Selected mode: AES-{mode}")
    
    input("\n[Press Enter to continue...]")
    
    
    print_section("STEP 3: GENERATE IV/NONCE")
    
    print("\nIV/Nonce should be generated from Task 4 PRNG.")
    print("For AES, IV must be 16 bytes (128 bits).")
    
    print("\nChoose IV generation:")
    print("1. Generate random IV (using os.urandom)")
    print("2. Enter custom IV (hex format)")
    
    while True:
        iv_choice = input("\nEnter choice (1 or 2): ").strip()
        if iv_choice in ['1', '2']:
            break
        print(" Invalid!")
    
    if iv_choice == '1':
        iv = os.urandom(16)  # 16 bytes for AES
        print(f" Random IV generated")
    else:
        print("\n Enter IV (32 hex characters for 16 bytes):")
        iv_hex = input("IV (hex): ").strip()
        try:
            iv = bytes.fromhex(iv_hex)
            if len(iv) != 16:
                print(f"  IV should be 16 bytes! Adjusting...")
                iv = (iv * 2)[:16]
        except ValueError:
            print(" Invalid hex! Generating random IV...")
            iv = os.urandom(16)
    
    print(f" IV: {bytes_to_hex(iv)}")
    
    input("\n[Press Enter to continue...]")
    
    
    print_section("STEP 4: ENTER MESSAGE")
    
    print("\n Enter the message you want to send to Bob:")
    print("(This is the plaintext message)")
    
    plaintext = ""
    while not plaintext:
        plaintext = input("\nMessage: ").strip()
        if not plaintext:
            print(" Message cannot be empty!")
    
    print(f"\n Message to send: \"{plaintext}\"")
    print(f"  Length: {len(plaintext)} characters")
    
    input("\n[Press Enter to encrypt...]")
    

    print_section("STEP 5: AUTHENTICATED ENCRYPTION")
    
    print("\n Performing Encrypt-then-MAC...")
    
    result = sm.authenticated_encrypt(
        plaintext=plaintext,
        encryption_key=encryption_key,
        hmac_key=hmac_key,
        iv=iv,
        mode=mode
    )
    

    print_section("STEP 6: ENCRYPTION RESULTS")
    
    print(f"\n{'='*70}")
    print("INPUTS TO SYMMETRIC ENCRYPTION:")
    print(f"{'='*70}")
    print(f"Plaintext: \"{plaintext}\"")
    print(f"Key (hex): {bytes_to_hex(encryption_key)}")
    print(f"IV (hex):  {bytes_to_hex(iv)}")
    print(f"Mode:      AES-{mode}")
    
    print(f"\n{'='*70}")
    print("OUTPUT OF SYMMETRIC ENCRYPTION:")
    print(f"{'='*70}")
    print(f"Ciphertext (hex): {bytes_to_hex(result['ciphertext'])}")
    print(f"Length: {len(result['ciphertext'])} bytes")
    
    print(f"\n{'='*70}")
    print("INPUTS TO HMAC:")
    print(f"{'='*70}")
    print(f"Message (ciphertext, hex): {bytes_to_hex(result['ciphertext'])}")
    print(f"HMAC Key (hex): {bytes_to_hex(hmac_key)}")
    
    print(f"\n{'='*70}")
    print("OUTPUT OF HMAC:")
    print(f"{'='*70}")
    print(f"HMAC (hex): {result['hmac'].hex()}")
    print(f"Length: {len(result['hmac'])} bytes ({len(result['hmac'])*8} bits)")
    
    print(f"\n{'='*70}")
    print("FINAL OUTPUT (Authenticated Ciphertext):")
    print(f"{'='*70}")
    print(f"Combined = Ciphertext || HMAC")
    print(f"Length: {len(result['combined'])} bytes")
    print(f"Hex: {bytes_to_hex(result['combined'], max_length=80)}")
    
    print_section("STEP 7: SAVE FOR BOB")
    
    filename = "alice_message.txt"
    
    with open(filename, 'w') as f:
        f.write(f"ENCRYPTION_MODE:\n{mode}\n\n")
        f.write(f"IV:\n{iv.hex()}\n\n")
        f.write(f"CIPHERTEXT:\n{result['ciphertext'].hex()}\n\n")
        f.write(f"HMAC:\n{result['hmac'].hex()}\n\n")
        f.write(f"COMBINED:\n{result['combined'].hex()}\n\n")
        f.write(f"ENCRYPTION_KEY:\n{encryption_key.hex()}\n\n")
        f.write(f"HMAC_KEY:\n{hmac_key.hex()}\n")
    
    print(f"\n Secure message saved to: {filename}")
    print(f" Location: {os.path.abspath(filename)}")
    print(f"\n Bob can now run bob_receive.py to decrypt!")
    
    print_section("ALICE'S SESSION SUMMARY")
    
    print(f"""
SECURE MESSAGE SENDING COMPLETE!
{'='*70}

ORIGINAL MESSAGE:
  "{plaintext}"

ENCRYPTION PROCESS:
  1. Plaintext → AES-{mode} Encryption → Ciphertext
  2. Ciphertext → HMAC-SHA256 → MAC
  3. Output: Ciphertext || MAC

RESULTS:
  Ciphertext: {len(result['ciphertext'])} bytes
  HMAC:       {len(result['hmac'])} bytes (32 bytes)
  Combined:   {len(result['combined'])} bytes

SECURITY:
  Confidentiality: AES-{mode} encryption
  Integrity: HMAC-SHA256
  Authentication: MAC verifies sender

Message ready for Bob!
    """)
    
    print("="*70)
    print(f"Session completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Program interrupted.")