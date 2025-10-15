from digital_signature import DigitalSignature, print_section
from datetime import datetime


def main():
    print("\n" + "="*70)
    print("BOB'S TERMINAL - FULLY INTERACTIVE VERSION")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    ds = DigitalSignature()
    
    print_section("STEP 1: BOB GENERATES KEYS")
    
    # User must choose key size
    print("\nSelect RSA key size:")
    print("1. 2048 bits (Standard - Recommended)")
    print("2. 3072 bits (High Security)")
    print("3. 4096 bits (Maximum Security)")
    
    while True:
        key_choice = input("\nEnter your choice (1, 2, or 3): ").strip()
        if key_choice in ['1', '2', '3']:
            break
        print("Invalid choice! Please enter 1, 2, or 3.")
    
    key_size_map = {'1': 2048, '2': 3072, '3': 4096}
    key_size = key_size_map[key_choice]
    
    print(f"\nYou selected: {key_size} bits")
    
    bob_private_key, bob_public_key = ds.generate_keys(key_size=key_size)
    ds.display_key_info("Bob", bob_public_key)
    
    input("\n[Press Enter to continue...]")
    
    print_section("STEP 2: RECEIVE DATA FROM ALICE")
    
    print()
    
    
    print("="*70)
    print("Step 2a: Paste Alice's MESSAGE")
    print("="*70)
    alice_message = ""
    while not alice_message:
        alice_message = input("Paste MESSAGE here: ").strip()
        if not alice_message:
            print("Message cannot be empty! Please paste the message from Alice.")
    
    print(f"Message received: \"{alice_message[:60]}{'...' if len(alice_message) > 60 else ''}\"")
    
    print("\n" + "="*70)
    print("Step 2b: Paste Alice's SIGNATURE (Base64)")
    print("="*70)
    alice_signature_b64 = ""
    while not alice_signature_b64:
        alice_signature_b64 = input("Paste SIGNATURE here: ").strip()
        if not alice_signature_b64:
            print("Signature cannot be empty! Please paste the signature from Alice.")
    
    print(f"Signature received: {len(alice_signature_b64)} characters")
    
    print("\n" + "="*70)
    print("Step 2c: Paste Alice's PUBLIC KEY")
    print("="*70)
    print("Paste the entire key (from -----BEGIN to -----END):")
    
    alice_public_key_pem = ""
    while not alice_public_key_pem:
        alice_public_key_pem = input("Paste PUBLIC KEY here: ").strip()
        if not alice_public_key_pem:
            print("Public key cannot be empty! Please paste the public key from Alice.")
        elif "-----BEGIN PUBLIC KEY-----" not in alice_public_key_pem:
            print("Invalid format! Key must contain '-----BEGIN PUBLIC KEY-----'")
            alice_public_key_pem = ""
    
    print(f"Public key received")
    
    # Validate and convert data
    print("\n Processing received data...")
    try:
        alice_signature = ds.base64_to_signature(alice_signature_b64)
        alice_public_key = ds.import_public_key(alice_public_key_pem)
        print("All data converted successfully!")
    except Exception as e:
        print(f"\n ERROR processing data: {e}")
        print("\nCheck all content I pasted")
        return
    
    print(f"\n{'='*70}")
    print("DATA RECEIVED FROM ALICE:")
    print(f"{'='*70}")
    print(f"  Message: {alice_message[:50]}{'...' if len(alice_message) > 50 else ''}")
    print(f"  Signature: {len(alice_signature_b64)} characters")
    print(f"  Public Key: Valid format ✓")
    print(f"{'='*70}")
    
    input("\n[Press Enter to verify signature...]")
    
    print_section("STEP 3: VERIFY WITH ALICE'S KEY (Correct)")
    
    print(f"\n Bob received this message from Alice:")
    print("-" * 70)
    print(f'"{alice_message}"')
    print("-" * 70)
    
    print(f"\n Verifying signature using Alice's public key...")
    print("   (This SHOULD succeed - Expected result: 1)")
    
    result_correct = ds.verify_signature(alice_message, alice_signature, alice_public_key)
    
    print(f"\n{'-'*70}")
    print(f"VERIFICATION RESULT: {result_correct}")
    print(f"EXPECTED: 1 (Valid)")
    print(f"{'-'*70}")
    
    if result_correct == 1:
        print("TEST PASSED: Alice's signature is VALID!")
        print(" Message authenticity confirmed")
        print(" Bob can trust this message came from Alice")
    else:
        print(" TEST FAILED: Signature should be valid with Alice's key!")
        print(" Check if you pasted the correct data")
    
    input("\n[Press Enter for next test...]")
    
    print_section("STEP 4: VERIFY WITH BOB'S KEY (Wrong)")
    
    print(f"\n Now verifying with Bob's own public key...")
    print("   (This SHOULD fail - Expected result: 0)")
    print("   (Signature was created with Alice's private key, not Bob's)")
    
    result_wrong = ds.verify_signature(alice_message, alice_signature, bob_public_key)
    
    print(f"\n{'-'*70}")
    print(f"VERIFICATION RESULT: {result_wrong}")
    print(f"EXPECTED: 0 (Invalid)")
    print(f"{'-'*70}")
    
    if result_wrong == 0:
        print("TEST PASSED: Signature is INVALID with wrong key!")
        print(" This proves the signature is tied to Alice's private key")
        print(" Security working correctly!")
    else:
        print("TEST FAILED: Signature should be invalid with Bob's key!")
    
    input("\n[Press Enter to create Bob's reply...]")
    
    print_section("STEP 5: BOB CREATES REPLY")
    
    print("\nEnter Bob's reply message to Alice:")
    print("(You MUST enter a message - no defaults)")
    
    bob_message = ""
    while not bob_message:
        bob_message = input("\nYour reply: ").strip()
        if not bob_message:
            print(" Message cannot be empty! Please enter a reply message.")
    
    print(f"\n✓ Your message: \"{bob_message}\"")
    
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signing Bob's message...")
    bob_signature = ds.sign_message(bob_message, bob_private_key)
    bob_signature_b64 = ds.signature_to_base64(bob_signature)
    
    print_section("STEP 6: COPY THIS TO ALICE'S TERMINAL")
    
    print("\n" + "-"*70)
    print("- START COPYING FROM NEXT LINE")
    print("-"*70)
    print()
    print("MESSAGE:")
    print(bob_message)
    print()
    print("SIGNATURE:")
    print(bob_signature_b64)
    print()
    print("PUBLIC_KEY:")
    print(ds.export_public_key(bob_public_key).strip())
    print()
    print("-"*70)
    print("- STOP COPYING AT PREVIOUS LINE")
    print("-"*70)
    
    print_section("BOB'S SESSION COMPLETE")
    
    all_passed = (result_correct == 1 and result_wrong == 0)
    
    print("The data block above is ready for Alice!")
    
    print("="*70)
    print(f"Session completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        print("="*70 + "\n")