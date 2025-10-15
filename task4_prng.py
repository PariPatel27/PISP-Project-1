from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time
import struct
from datetime import datetime


class PseudoRandomNumberGenerator:
    # Pseudo-random number generator that uses SHA-256
    
    def __init__(self):
        self.backend = default_backend()
        self.state = None  # Internal state (will be set by seed)
        self.counter = 0   # Counter for generating different values
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] PRNG initialized")
        print("  State: Not seeded yet")
    
    def seed(self, seed_value=None):
        #it will initialize the random numbers
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Seeding PRNG...")
        
        if seed_value is None:
            # Use current time as seed
            seed_value = int(time.time() * 1000000)  # Microseconds
            print(f"  Using default seed (current time): {seed_value}")
        else:
            print(f"  Using provided seed: {seed_value}")
        
        # Convert seed to bytes
        if isinstance(seed_value, int):
            seed_bytes = str(seed_value).encode('utf-8')
        elif isinstance(seed_value, str):
            seed_bytes = seed_value.encode('utf-8')
        else:
            seed_bytes = bytes(seed_value)
        
        # Hash the seed to create initial state
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(seed_bytes)
        self.state = digest.finalize()
        
        # Reset counter
        self.counter = 0
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✓ PRNG seeded!")
        print(f"  Internal state: {self.state.hex()[:32]}...")
        print(f"  Counter reset to: 0")
    
    def reseed(self, additional_seed):
        #reseed will add more randomness to the random numbers
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Re-seeding PRNG...")
        
        if self.state is None:
            print("  Warning: PRNG not seeded yet. Performing initial seed.")
            self.seed(additional_seed)
            return
        
        print(f"  Adding entropy: {additional_seed}")
        
        # Convert additional seed to bytes
        if isinstance(additional_seed, int):
            add_bytes = str(additional_seed).encode('utf-8')
        elif isinstance(additional_seed, str):
            add_bytes = additional_seed.encode('utf-8')
        else:
            add_bytes = bytes(additional_seed)
        
        # Mix new seed with current state
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(self.state)      # Current state
        digest.update(add_bytes)        # New  for randomness
        self.state = digest.finalize()
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✓ Re-seeding complete!")
        print(f"  New internal state: {self.state.hex()[:32]}...")
    
    def generate(self, output_bytes=32):
        #it will generate random numbers
        if self.state is None:
            print(" ERROR: PRNG not seeded! Call seed() first.")
            return None
        
        # Increment counter
        self.counter += 1
        
        # Create input for hash: state || counter
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(self.state)
        digest.update(struct.pack('<Q', self.counter))  # Add counter as 8 bytes
        
        # Generate random bytes
        random_bytes = digest.finalize()
        
        # If need more bytes, keep hashing
        while len(random_bytes) < output_bytes:
            digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
            digest.update(random_bytes)
            random_bytes += digest.finalize()
        
        # Return requested number of bytes
        return random_bytes[:output_bytes]
    
    def generate_int(self, max_value=None):
        #it will generate random integers
        random_bytes = self.generate(32)
        
        # Convert bytes to integer
        random_int = int.from_bytes(random_bytes, byteorder='big')
        
        if max_value:
            random_int = random_int % max_value
        
        return random_int
    
    def get_state_info(self):
        #current state
        if self.state is None:
            return "Not seeded"
        return {
            'state_hex': self.state.hex(),
            'counter': self.counter
        }


def print_section(title):

    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")


def main():
    print("\n" + "="*70)
    print("TASK 4: PSEUDO-RANDOM NUMBER GENERATOR (PRNG)")
    print("Generating Random Numbers for Symmetric Encryption")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    prng = PseudoRandomNumberGenerator()
    
    
    print_section("DEMONSTRATION 1: RANDOMNESS")
    
    print("\nThis demonstrates that generated numbers APPEAR random.")
    print("I'll seed the PRNG and generate a sequence of random numbers.")
    
    print("\n Enter seed value for first demonstration:")
    print("(Enter a number, text, or press Enter for time-based seed)")
    
    seed1_input = input("Seed value: ").strip()
    
    if not seed1_input:
        seed1 = None  # Will use time as we seed current time above
    else:
        try:
            seed1 = int(seed1_input)
        except ValueError:
            seed1 = seed1_input  # Use as string
    
    # Seed the PRNG
    prng.seed(seed1)
    
    print("\n How many random numbers to generate?")
    print("(Common: 10-20 for demonstration)")
    
    while True:
        try:
            count1 = int(input("Count: ").strip())
            if count1 < 1:
                print(" Must be at least 1!")
                continue
            break
        except ValueError:
            print(" Invalid! Enter a number.")
    
    print(f"\n Generating {count1} random numbers...")
    print(f"{'='*70}")
    print(f"{'#':<5} {'Random Number (Decimal)':<30} {'Hex (first 16 chars)':<20}")
    print(f"{'-'*70}")
    
    sequence1 = []
    for i in range(count1):
        random_num = prng.generate_int()
        sequence1.append(random_num)
        hex_preview = hex(random_num)[2:18]
        print(f"{i+1:<5} {random_num:<30} {hex_preview:<20}")
    
    print(f"{'='*70}")
    print(" Numbers appear random (no obvious pattern)")
    
    input("\n[Press Enter to continue...]")
    
    print_section("DEMONSTRATION 2: DETERMINISTIC")
    
    print("\nThis demonstrates that SAME seed produces SAME sequence.")
    print("We'll generate two sequences with the SAME seed.")
    
    print("\n Enter seed value for deterministic test:")
    print("(This will be used for BOTH sequences)")
    
    seed2_input = input("Seed value: ").strip()
    
    if not seed2_input:
        seed2 = 12345  # Default for demo
        print(f"(Using default: {seed2})")
    else:
        try:
            seed2 = int(seed2_input)
        except ValueError:
            seed2 = seed2_input
    
    print("\n How many numbers per sequence?")
    
    while True:
        try:
            count2 = int(input("Count: ").strip())
            if count2 < 1:
                print(" Must be at least 1!")
                continue
            if count2 > 50:
                print("  Large count! Recommend 5-15 for clear comparison.")
                confirm = input("Continue? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue
            break
        except ValueError:
            print(" Invalid!")
    
    # Generate FIRST sequence
    print(f"\n SEQUENCE 1 (Seed: {seed2}):")
    print(f"{'='*70}")
    
    prng_seq1 = PseudoRandomNumberGenerator()
    prng_seq1.seed(seed2)
    
    sequence2a = []
    for i in range(count2):
        random_num = prng_seq1.generate_int()
        sequence2a.append(random_num)
        print(f"  {i+1}. {random_num}")
    
    # Generate SECOND sequence with SAME seed
    print(f"\n SEQUENCE 2 (Seed: {seed2}) - SAME SEED:")
    print(f"{'='*70}")
    
    prng_seq2 = PseudoRandomNumberGenerator()
    prng_seq2.seed(seed2)
    
    sequence2b = []
    for i in range(count2):
        random_num = prng_seq2.generate_int()
        sequence2b.append(random_num)
        print(f"  {i+1}. {random_num}")
    
    # Compare sequences
    print(f"\n{'='*70}")
    print("COMPARISON:")
    print(f"{'='*70}")
    
    if sequence2a == sequence2b:
        print(" SEQUENCES ARE IDENTICAL!")
        print(" Same seed -> Same sequence (Deterministic)")
        print(" This is CORRECT behavior for PRNG!")
    else:
        print("✗✗✗ SEQUENCES ARE DIFFERENT!")
        print("✗ ERROR: Same seed should produce same sequence!")
    
    input("\n[Press Enter to continue...]")
    
    print_section("DEMONSTRATION 3: SEEDING IMPACT")
    
    print("\nThis demonstrates that DIFFERENT seeds produce DIFFERENT sequences.")
    
    print("\n Enter FIRST seed value:")
    seed3a_input = input("Seed 1: ").strip()
    
    if not seed3a_input:
        seed3a = 11111
        print(f"(Using default: {seed3a})")
    else:
        try:
            seed3a = int(seed3a_input)
        except ValueError:
            seed3a = seed3a_input
    
    print("\n Enter SECOND seed value (DIFFERENT from first):")
    seed3b_input = input("Seed 2: ").strip()
    
    if not seed3b_input:
        seed3b = 99999
        print(f"(Using default: {seed3b})")
    else:
        try:
            seed3b = int(seed3b_input)
        except ValueError:
            seed3b = seed3b_input
    
    # Warn if seeds are the same
    if seed3a == seed3b:
        print("  Warning: You entered the SAME seed twice!")
        print("   Sequences will be identical. Use different values for contrast.")
    
    print("\n How many numbers per sequence?")
    
    while True:
        try:
            count3 = int(input("Count: ").strip())
            if count3 < 1:
                print(" Must be at least 1!")
                continue
            break
        except ValueError:
            print(" Invalid!")
    
    # Generate FIRST sequence
    print(f"\n SEQUENCE 1 (Seed: {seed3a}):")
    print(f"{'='*70}")
    
    prng_diff1 = PseudoRandomNumberGenerator()
    prng_diff1.seed(seed3a)
    
    sequence3a = []
    for i in range(count3):
        random_num = prng_diff1.generate_int()
        sequence3a.append(random_num)
        print(f"  {i+1}. {random_num}")
    
    # Generate SECOND sequence with DIFFERENT seed
    print(f"\n🎲 SEQUENCE 2 (Seed: {seed3b}) - DIFFERENT SEED:")
    print(f"{'='*70}")
    
    prng_diff2 = PseudoRandomNumberGenerator()
    prng_diff2.seed(seed3b)
    
    sequence3b = []
    for i in range(count3):
        random_num = prng_diff2.generate_int()
        sequence3b.append(random_num)
        print(f"  {i+1}. {random_num}")
    
    # Compare sequences
    print(f"\n{'='*70}")
    print("COMPARISON:")
    print(f"{'='*70}")
    
    if sequence3a != sequence3b:
        print(" SEQUENCES ARE DIFFERENT!")
        print(" Different seeds -> Different sequences")
        print(" Seeding has IMPACT on output!")
    else:
        print("  SEQUENCES ARE IDENTICAL!")
        if seed3a == seed3b:
            print("   (This is expected - you used the same seed)")
        else:
            print("   (Unexpected - different seeds should give different sequences)")
    
    input("\n[Press Enter to continue...]")
    
    print_section("DEMONSTRATION 4: RE-SEEDING")
    
    print("\nThis demonstrates adding more randomness (re-seeding).")
    
    print("\n Enter initial seed:")
    reseed_init = input("Initial seed: ").strip()
    
    if not reseed_init:
        reseed_init = 55555
        print(f"(Using default: {reseed_init})")
    else:
        try:
            reseed_init = int(reseed_init)
        except ValueError:
            pass
    
    # Seed PRNG
    prng_reseed = PseudoRandomNumberGenerator()
    prng_reseed.seed(reseed_init)
    
    print("\n🎲 Generating 3 numbers BEFORE re-seeding:")
    before_reseed = []
    for i in range(3):
        num = prng_reseed.generate_int()
        before_reseed.append(num)
        print(f"  {i+1}. {num}")
    
    # Re-seed
    print("\n Enter additional seed for re-seeding:")
    reseed_add = input("Additional seed: ").strip()
    
    if not reseed_add:
        reseed_add = 77777
        print(f"(Using default: {reseed_add})")
    else:
        try:
            reseed_add = int(reseed_add)
        except ValueError:
            pass
    
    prng_reseed.reseed(reseed_add)
    
    print("\n Generating 3 numbers AFTER re-seeding:")
    after_reseed = []
    for i in range(3):
        num = prng_reseed.generate_int()
        after_reseed.append(num)
        print(f"  {i+1}. {num}")
    
    print(f"\n{'='*70}")
    print("OBSERVATION:")
    print(f"{'='*70}")
    print(" Numbers after re-seeding are DIFFERENT")
    print(" Re-seeding changes the random sequence")
    print(" Useful for adding entropy during operation")
    
  
    print("="*70)
    print(f"Session completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Program interrupted by user.")
        print("="*70 + "\n")
