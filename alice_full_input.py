from digital_signature import DigitalSignature, print_section
from datetime import datetime


def main():
    
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    ds = DigitalSignature()
    
    
    print_section("STEP 1: ALICE GENERATES KEYS")
    
    # User must choose key size
    print("\nSelect RSA key size:")
    print("1. 2048 bits (Standard - Recommended)")
    print("2. 3072 bits (High Security)")
    print("3. 4096 bits (Maximum Security)")
    
    while True:
        key_choice = input("\nEnter your choice (1, 2, or 3): ").strip()
        if key_choice in ['1', '2', '3']:
            break
        print(" Invalid choice! Please enter 1, 2, or 3.")
    
    key_size_map = {'1': 2048, '2': 3072, '3': 4096}
    key_size = key_size_map[key_choice]
    
    print(f"\n You selected: {key_size} bits")
    
    alice_private_key, alice_public_key = ds.generate_keys(key_size=key_size)
    ds.display_key_info("Alice", alice_public_key)
    
    input("\n[Press Enter to continue...]")
    
    
    print_section("STEP 2: ALICE CREATES MESSAGE")
    
    print("\n Enter the message you want to send to Bob:")
    print("(You MUST enter a message - no defaults)")
    
    message = ""
    while not message:
        message = input("\nYour message: ").strip()
        if not message:
            print(" Message cannot be empty! Please enter a message.")
    
    print(f"\n Your message: \"{message}\"")
    
    # Hash and sign
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Computing hash and signing...")
    ds.hash_message(message)
    print()
    signature = ds.sign_message(message, alice_private_key)
    signature_b64 = ds.signature_to_base64(signature)
    
    print_section("STEP 3: COPY THIS TO BOB'S TERMINAL")
    
    print("\n" + "-"*70)
    print("- START COPYING FROM NEXT LINE")
    print("-"*70)
    print()
    print("MESSAGE:")
    print(message)
    print()
    print("SIGNATURE:")
    print(signature_b64)
    print()
    print("PUBLIC_KEY:")
    print(ds.export_public_key(alice_public_key).strip())
    print()
    print("-"*70)
    print("- STOP COPYING AT PREVIOUS LINE")
    print("-"*70)
    
    
    print_section("STEP 4: ALICE'S SELF-VERIFICATION TESTS")
    
    print("\n🔍 Test 1: Verify with Alice's own public key")
    print("   (This SHOULD succeed - Expected result: 1)")
    result1 = ds.verify_signature(message, signature, alice_public_key)
    
    print(f"\n{'='*70}")
    print(f"VERIFICATION RESULT: {result1}")
    print(f"EXPECTED: 1 (Valid)")
    print(f"{'='*70}")
    
    if result1 == 1:
        print(" TEST PASSED: Signature is valid with correct key!")
    else:
        print(" TEST FAILED: Something went wrong!")
    
    input("\n[Press Enter for next test...]")
    
    print("\n Test 2: Verify with a different (wrong) public key")
    print("   (This SHOULD fail - Expected result: 0)")
    print("   Generating a random key to simulate wrong key...")
    
    _, wrong_key = ds.generate_keys(key_size=2048)
    result2 = ds.verify_signature(message, signature, wrong_key)
    
    print(f"\n{'='*70}")
    print(f"VERIFICATION RESULT: {result2}")
    print(f"EXPECTED: 0 (Invalid)")
    print(f"{'='*70}")
    
    if result2 == 0:
        print(" TEST PASSED: Signature correctly fails with wrong key!")
    else:
        print(" TEST FAILED: Signature should be invalid with wrong key!")
    
    print_section("ALICE'S SESSION COMPLETE")
    
    all_passed = (result1 == 1 and result2 == 0)
    
    print(f"""
SESSION SUMMARY:
{'='*70}
Generated RSA keys ({key_size} bits)
Created custom message: "{message[:50]}{'...' if len(message) > 50 else ''}"
Computed message hash (SHA-256)
Signed message with private key
Self-verification: {result1} (Expected: 1) {' PASS' if result1 == 1 else ' FAIL'}
Wrong key test: {result2} (Expected: 0) {' PASS' if result2 == 0 else ' FAIL'}
{'='*70}

OVERALL: {' ALL TESTS PASSED ' if all_passed else ' SOME TESTS FAILED '}

The data block above is ready for Bob! Now run bob_full_input.py in another terminal!
    """)
    
    print("="*70)
    print(f"Session completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Program interrupted by user.")
        print("="*70 + "\n")