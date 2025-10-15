from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from datetime import datetime
import os


#using digital signature file to generate keys and sign messages
class DigitalSignature:
    def __init__(self):
        self.backend = default_backend()
    
    def generate_keys(self, key_size=2048):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Generating RSA key pair ({key_size} bits)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=self.backend
        )
        public_key = private_key.public_key()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Key pair generated!")
        return private_key, public_key
    
    def sign_message(self, message, private_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signing...")
        signature = private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signature created!")
        return signature
    
    def verify_signature(self, message, signature, public_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Verifying signature...")
        try:
            public_key.verify(
                signature, message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signature VALID")
            return 1
        except:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✗✗✗Signature INVALID")
            return 0
    
    def export_public_key(self, public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def signature_to_base64(self, signature):
        return base64.b64encode(signature).decode('utf-8')
    
    def display_key_info(self, name, public_key):
        key_numbers = public_key.public_numbers()
        print(f"\n{'='*70}")
        print(f"{name}'s RSA Public Key")
        print(f"{'='*70}")
        print(f"Size: {public_key.key_size} bits")
        print(f"Exponent: {key_numbers.e}")
        print(f"Modulus: {str(key_numbers.n)[:60]}...")
        print(f"{'='*70}")

class DiffieHellman:
    def __init__(self):
        self.ds = DigitalSignature()
        self.p = None
        self.g = None
    
    def generate_large_prime(self, bits=512):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Generating {bits}-bit prime...")
        safe_primes = {
            256: 2**255 + 19,
            512: 2**521 - 1,
            1024: 2**1024 - 159
        }
        prime = safe_primes.get(bits, 2**255 + 19)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Prime generated!")
        return prime
    
    def set_public_parameters(self, p, g):
        self.p = p
        self.g = g
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Public parameters set")
    
    def generate_secret(self):
        secret = secrets.randbelow(self.p - 2) + 1
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Secret generated")
        return secret
    
    def compute_public_value(self, secret, name="Alice"):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {name} computing g^secret mod p...")
        public_value = pow(self.g, secret, self.p)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Computed!")
        return public_value
    
    def compute_shared_secret(self, received_value, own_secret, name="Alice"):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {name} computing shared secret...")
        shared_secret = pow(received_value, own_secret, self.p)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Shared secret computed!")
        return shared_secret


def print_section(title):
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")

def main():
    print("\n" + "="*70)
    print("ALICE'S TERMINAL - DIFFIE-HELLMAN KEY EXCHANGE")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    dh = DiffieHellman()
    
    print_section("STEP 1: GENERATE RSA KEYS")
    
    print("\nSelect RSA key size:")
    print("1. 2048 bits ")
    print("2. 3072 bits")
    
    while True:
        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice in ['1', '2']:
            break
        print("Invalid!")
    
    rsa_size = 2048 if choice == '1' else 3072
    alice_private_key, alice_public_key = dh.ds.generate_keys(key_size=rsa_size)
    dh.ds.display_key_info("Alice", alice_public_key)
    
    input("\n[Press Enter...]")
    
    print_section("STEP 2: DH PARAMETERS")
    
    print("\nChoose DH parameters:")
    print("1. Auto-generate (Recommended)")
    print("2. Enter custom values")
    
    while True:
        param_choice = input("\nEnter choice (1 or 2): ").strip()
        if param_choice in ['1', '2']:
            break
        print("Invalid!")
    
    if param_choice == '1':
        print("\nSelect prime size:")
        print("1. 256 bits (Fast)")
        print("2. 512 bits (Standard)")
        
        while True:
            size_choice = input("\nEnter choice (1 or 2): ").strip()
            if size_choice in ['1', '2']:
                break
            print("Invalid!")
        
        p = dh.generate_large_prime(bits=256 if size_choice == '1' else 512)
        g = 2
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Generator (g): {g}")
    else:
        while True:
            try:
                p = int(input("\nEnter prime (p): ").strip())
                if p < 10:
                    print("Too small!")
                    continue
                break
            except ValueError:
                print("Invalid number!")
        
        while True:
            try:
                g = int(input("Enter generator (g): ").strip())
                if g >= p or g < 2:
                    print(f" Must be between 2 and {p-1}")
                    continue
                break
            except ValueError:
                print(" Invalid number!")
    
    dh.set_public_parameters(p, g)
    
    print(f"\n{'='*70}")
    print("PUBLIC PARAMETERS")
    print(f"{'='*70}")
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print(f"{'='*70}")
    
    input("\n[Press Enter...]")
    

    print_section("STEP 3: ALICE'S SECRET")
    
    print("\nChoose secret:")
    print("1. Auto-generate (Recommended)")
    print("2. Enter custom value")
    
    while True:
        secret_choice = input("\nEnter choice (1 or 2): ").strip()
        if secret_choice in ['1', '2']:
            break
        print("Invalid!")
    
    if secret_choice == '1':
        alice_secret = dh.generate_secret()
        print(f"Secret (a): {str(alice_secret)[:60]}... (private!)")
    else:
        while True:
            try:
                alice_secret = int(input("\nEnter secret (a): ").strip())
                if alice_secret >= p or alice_secret < 1:
                    print(f" Must be between 1 and {p-1}")
                    continue
                print(f" Secret set")
                break
            except ValueError:
                print(" Invalid!")
    
    input("\n[Press Enter...]")
    

    print_section("STEP 4: COMPUTE PUBLIC VALUE") #g^a mod p
    
    alice_public_value = dh.compute_public_value(alice_secret, "Alice")
    
    print(f"\n{'='*70}")
    print(f"Alice's public value (g^a mod p):")
    print(f"  {alice_public_value}")
    print(f"{'='*70}")
    
    input("\n[Press Enter...]")
    

    print_section("STEP 5: SIGN PUBLIC VALUE")
    
    alice_signature = dh.ds.sign_message(str(alice_public_value), alice_private_key)
    alice_sig_b64 = dh.ds.signature_to_base64(alice_signature)
    

    print_section("STEP 6: SAVE FOR BOB")
    
    filename = "alice_dh_data.txt"
    with open(filename, 'w') as f:
        f.write(f"DH_PRIME:\n{p}\n\n")
        f.write(f"DH_GENERATOR:\n{g}\n\n")
        f.write(f"ALICE_PUBLIC_VALUE:\n{alice_public_value}\n\n")
        f.write(f"ALICE_SIGNATURE:\n{alice_sig_b64}\n\n")
        f.write(f"ALICE_RSA_PUBLIC_KEY:\n{dh.ds.export_public_key(alice_public_key)}\n")
    
    print(f"\n Saved to: {filename}")
    print(f" Now run bob_diffie.py in another terminal!")
    
    input("\n[Press Enter to wait for Bob...]")
    

    print_section("STEP 7: WAITING FOR BOB")
    
    bob_filename = "bob_dh_data.txt"
    while not os.path.exists(bob_filename):
        input(f" Waiting for {bob_filename}... Press Enter to check...")
    
    print(f" File found!")
    
    with open(bob_filename, 'r') as f:
        content = f.read()
    
    bob_public_value = int(content.split("BOB_PUBLIC_VALUE:\n")[1].split("\n\n")[0])
    bob_sig_b64 = content.split("BOB_SIGNATURE:\n")[1].split("\n\n")[0]
    bob_rsa_pem = content.split("BOB_RSA_PUBLIC_KEY:\n")[1]
    
    bob_signature = base64.b64decode(bob_sig_b64)
    bob_public_key = serialization.load_pem_public_key(
        bob_rsa_pem.encode('utf-8'), backend=default_backend()
    )
    
    print(f" Bob's g^b mod p: {str(bob_public_value)[:60]}...")
    
    input("\n[Press Enter to verify...]")
    

    print_section("STEP 8: VERIFY BOB'S SIGNATURE")
    
    result = dh.ds.verify_signature(str(bob_public_value), bob_signature, bob_public_key)
    
    print(f"\n{'='*70}")
    print(f"VERIFICATION RESULT: {result}")
    print(f"EXPECTED: 1")
    print(f"{'='*70}")
    
    if result == 1:
        print("Bob's signature is valid!")
    
    input("\n[Press Enter...]")
    

    print_section("STEP 9: COMPUTE SHARED SECRET")
    
    shared_secret = dh.compute_shared_secret(bob_public_value, alice_secret, "Alice")
    
    print(f"\n{'='*70}")
    print("SHARED SECRET")
    print(f"{'='*70}")
    print(f"Alice's shared secret (K = g^ab mod p):")
    print(f"  {shared_secret}")
    print(f"{'='*70}")
    
    print_section("ALICE'S SESSION COMPLETE")
    
    print(f"""
Generated RSA keys ({rsa_size} bits)
DH Parameters: p={str(p)[:40]}..., g={g}
Alice's g^a mod p: {str(alice_public_value)[:40]}...
Signature created and sent
Bob's signature verified: {result}
Shared secret computed: {str(shared_secret)[:40]}...

Check Bob's terminal to see if secrets match!
    """)
    
    print("="*70)
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrupted.")
