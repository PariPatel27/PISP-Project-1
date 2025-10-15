from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import time


class KeyDerivationFunction:
    #Simple KDF using iterative hashing
    #Takes a shared secret and hashes it N times to derive a strong encryption key
    
    def __init__(self, hash_algorithm='SHA256'):
        """
        Initialize KDF with chosen hash algorithm.
        
        Args:
            hash_algorithm (str): Hash function to use ('SHA256', 'SHA512')
        """
        self.backend = default_backend()
        self.hash_algorithm = hash_algorithm
        
        # Map algorithm names to cryptography hash objects
        self.hash_functions = {
            'SHA256': hashes.SHA256(),
            'SHA512': hashes.SHA512(),
            'SHA384': hashes.SHA384()
        }
        
        self.hash_func = self.hash_functions.get(hash_algorithm, hashes.SHA256())
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] KDF initialized")
        print(f"  Hash algorithm: {hash_algorithm}")
    
    def derive_key(self, shared_secret, iterations):
        # Start key derivation
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting key derivation...")
        print(f"  Input: Shared secret")
        print(f"  Iterations: {iterations:,}")
        print(f"  Hash function: {self.hash_algorithm}")
        
        # Convert shared secret to bytes
        if isinstance(shared_secret, int):
            shared_secret = str(shared_secret).encode('utf-8')
        elif isinstance(shared_secret, str):
            shared_secret = shared_secret.encode('utf-8')
        
        # Start with the shared secret
        current_hash = shared_secret
        
        # Track progress
        start_time = time.time()
        
        # Hash iteratively
        for i in range(iterations):
            # Create hash digest
            digest = hashes.Hash(self.hash_func, backend=self.backend)
            digest.update(current_hash)
            current_hash = digest.finalize()
            
            # Show progress for large iterations
            if iterations >= 1000 and (i + 1) % (iterations // 10) == 0:
                progress = ((i + 1) / iterations) * 100
                print(f"  Progress: {progress:.0f}% ({i + 1:,} / {iterations:,})")
        
        elapsed_time = time.time() - start_time
        
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Key derivation complete!")
        print(f"  Time taken: {elapsed_time:.3f} seconds")
        print(f"  Total iterations: {iterations:,}")
        
        return current_hash
    
    def display_key(self, key, name="Derived Encryption Key"):
        # Display key
        print(f"\n{'='*70}")
        print(f"{name.upper()}")
        print(f"{'='*70}")
        
        # Show in different formats
        print(f"Length: {len(key)} bytes ({len(key) * 8} bits)")
        print(f"\nHex Format:")
        print(f"  {key.hex()}")
        print(f"\nFirst 16 bytes (hex):")
        print(f"  {key[:16].hex()}")
        print(f"\nLast 16 bytes (hex):")
        print(f"  {key[-16:].hex()}")
        
        print(f"{'='*70}")


def print_section(title):
    #print title
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")


def main():
    print("\n" + "="*70)
    print("TASK 3: KEY DERIVATION FUNCTION (KDF)")
    print("Deriving Strong Encryption Key from Shared Secret")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
   
    print_section("STEP 1: SELECT HASH ALGORITHM")
    
    print("\nChoose hash algorithm for KDF:")
    print("1. SHA-256 (256-bit output, recommended)")
    print("2. SHA-384 (384-bit output)")
    print("3. SHA-512 (512-bit output, most secure)")
    
    while True:
        hash_choice = input("\nEnter your choice (1, 2, or 3): ").strip()
        if hash_choice in ['1', '2', '3']:
            break
        print(" Invalid! Please enter 1, 2, or 3.")
    
    hash_map = {
        '1': 'SHA256',
        '2': 'SHA384',
        '3': 'SHA512'
    }
    
    hash_algorithm = hash_map[hash_choice]
    print(f"\n Selected: {hash_algorithm}")
    
    # Initialize KDF
    kdf = KeyDerivationFunction(hash_algorithm=hash_algorithm)
    
    input("\n[Press Enter to continue...]")
    
    print_section("STEP 2: ENTER SHARED SECRET")
    
    print("\nThe shared secret is the value computed in Task 2 (g^ab mod p).")
    print("\nChoose how to provide the shared secret:")
    print("1. Enter the shared secret manually")
    print("2. Use a demo value")
    
    while True:
        secret_choice = input("\nEnter your choice (1 or 2): ").strip()
        if secret_choice in ['1', '2']:
            break
        print(" Invalid! Please enter 1 or 2.")
    
    if secret_choice == '1':
        print("\n Enter the shared secret from Task 2:")
        print("(This is the g^ab mod p value that Alice and Bob computed)")
        
        while True:
            shared_secret_input = input("\nShared secret: ").strip()
            if shared_secret_input:
                try:
                    # Try to convert to int (if it's a number)
                    shared_secret = int(shared_secret_input)
                    break
                except ValueError:
                    # If not a number, use as string
                    shared_secret = shared_secret_input
                    break
            else:
                print(" Shared secret cannot be empty!")
    else:
        # Demo value
        shared_secret = 54321098765432109876543210987654321098765432109876543210987654321098765432109
        print(f"\n Using demo value:")
        print(f"  {shared_secret}")
    
    print(f"\n Shared secret received:")
    print(f"  {str(shared_secret)[:70]}...")
    
    input("\n[Press Enter to continue...]")
    
    print_section("STEP 3: ENTER ITERATION COUNT")
    
    print("\nHow many times should we hash the shared secret?")
    print("\nCommon values:")
    print("  • 1,000 - Fast (for testing)")
    print("  • 10,000 - Standard (recommended)")
    print("  • 100,000 - High security (slower)")
    print("  • 1,000,000 - Maximum security (very slow)")
    
    print("\n Enter number of iterations:")
    
    while True:
        iterations_input = input("Iterations: ").strip()
        try:
            iterations = int(iterations_input)
            if iterations < 1:
                print(" Must be at least 1!")
                continue
            if iterations > 10000000:
                print(f"  Warning: {iterations:,} is very large. This will take a long time!")
                confirm = input("Continue anyway? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue
            break
        except ValueError:
            print(" Invalid! Please enter a number.")
    
    print(f"\n Iterations set: {iterations:,}")
    
    # Estimate time
    if iterations <= 1000:
        estimated = "< 1 second"
    elif iterations <= 10000:
        estimated = "1-2 seconds"
    elif iterations <= 100000:
        estimated = "10-20 seconds"
    else:
        estimated = f"{iterations // 10000} seconds"
    
    print(f"  Estimated time: {estimated}")
    
    input("\n[Press Enter to start key derivation...]")
    
    print_section("STEP 4: DERIVE ENCRYPTION KEY")
    
    print(f"\n Hashing shared secret {iterations:,} times...")
    print(f"   Each iteration: Hash(previous_hash)")
    print(f"   Building strong encryption key...\n")
    
    # Perform key derivation
    encryption_key = kdf.derive_key(shared_secret, iterations)
    
   
    print_section("STEP 5: DERIVED ENCRYPTION KEY")
    
    kdf.display_key(encryption_key, "Derived Encryption Key")
    
    # Show additional information
    print(f"\n{'='*70}")
    print("KEY DETAILS")
    print(f"{'='*70}")
    print(f"Input (Shared Secret): {str(shared_secret)[:60]}...")
    print(f"Hash Algorithm: {hash_algorithm}")
    print(f"Iterations: {iterations:,}")
    print(f"Output Key Length: {len(encryption_key)} bytes ({len(encryption_key) * 8} bits)")
    print(f"{'='*70}")
    
    print_section("STEP 6: COMPARISON - EFFECT OF ITERATIONS")
    
    print("\n Let's see how different iteration counts produce different keys:")
    print("(Using the same shared secret)")
    
    test_iterations = [1, 10, 100, 1000]
    
    print(f"\n{'Iterations':<12} {'Derived Key (first 32 hex chars)':<50}")
    print("-" * 70)
    
    for test_iter in test_iterations:
        if test_iter <= iterations:  # Only show if less than user's choice
            test_key = kdf.derive_key(shared_secret, test_iter)
            print(f"{test_iter:<12,} {test_key.hex()[:32]:<50}")
    
    print(f"{iterations:<12,} {encryption_key.hex()[:32]:<50} <- Your key")
    
    print("\n Notice: Different iterations = Different keys!")
    print(" More iterations = Slower to compute = Harder to brute force!")
    
 
    print_section("STEP 7: VERIFY CONSISTENCY")
    
    print("\n Verification: Running derivation again with same inputs...")
    print("   (Should produce IDENTICAL key)")
    
    verification_key = kdf.derive_key(shared_secret, iterations)
    
    if encryption_key == verification_key:
        print("\n✓✓✓ CONSISTENCY VERIFIED!")
        print("✓ Same input + Same iterations = Same key!")
        print("✓ Deterministic (reproducible) - important for encryption!")
    else:
        print("\n✗ ERROR: Keys don't match!")
        print("✗ Something is wrong with the implementation!")
    
   
    print_section("TASK 3: SESSION SUMMARY")
    
    print(f"""
KEY DERIVATION FUNCTION COMPLETE!
{'='*70}

INPUT:
  Shared Secret: {str(shared_secret)[:50]}...
  Hash Algorithm: {hash_algorithm}
  Iterations: {iterations:,}

OUTPUT:
  Encryption Key (hex): {encryption_key.hex()}
  Key Length: {len(encryption_key)} bytes ({len(encryption_key) * 8} bits)

PROCESS:
  Hash_0 = Hash(shared_secret)
  Hash_1 = Hash(Hash_0)
  Hash_2 = Hash(Hash_1)
  ...
  Hash_{iterations-1} = Hash(Hash_{iterations-2})
  
  Final Encryption Key = Hash_{iterations-1}

Meaning:
  Strong key derived from shared secret {iterations:,} iterations make brute force attacks harder
  Deterministic (same input = same output)
  Ready for symmetric encryption (AES, ChaCha20, etc.)

{'='*70}

 KEY DERIVATION SUCCESSFUL 

This key can now be used for symmetric encryption in Task 4!
    """)
    
    print("="*70)
    print(f"Session completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")
    
    print_section("OPTIONAL: SAVE KEY TO FILE")
    
    print("\nDo you want to save the derived key to a file?")
    save_choice = input("Save to file? (y/n): ").strip().lower()
    
    if save_choice == 'y':
        filename = "derived_encryption_key.txt"
        
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("DERIVED ENCRYPTION KEY\n")
            f.write("="*70 + "\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Hash Algorithm: {hash_algorithm}\n")
            f.write(f"Iterations: {iterations:,}\n")
            f.write(f"Key Length: {len(encryption_key)} bytes\n")
            f.write("="*70 + "\n\n")
            f.write("Encryption Key (Hexadecimal):\n")
            f.write(encryption_key.hex() + "\n\n")
            f.write("Shared Secret Used:\n")
            f.write(str(shared_secret) + "\n")
        
        print(f"\n Key saved to: {filename}")
        print(f" Location: {filename}")
    
    print("\n" + "="*70)
    print("Thank you for using the Key Derivation Function!")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Program interrupted by user.")
        print("="*70 + "\n")
