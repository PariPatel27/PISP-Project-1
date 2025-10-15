from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from datetime import datetime
import os


#used digital sign file for signing a msg and generate keys 
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
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Signature created!")
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
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Signature VALID ")
            return 1
        except:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Signature INVALID ")
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
    
    def set_public_parameters(self, p, g):
        self.p = p
        self.g = g
    
    def generate_secret(self):
        secret = secrets.randbelow(self.p - 2) + 1
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Secret generated")
        return secret
    
    def compute_public_value(self, secret, name="Bob"):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {name} computing g^secret mod p...")
        public_value = pow(self.g, secret, self.p)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Computed!")
        return public_value
    
    def compute_shared_secret(self, received_value, own_secret, name="Bob"):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {name} computing shared secret...")
        shared_secret = pow(received_value, own_secret, self.p)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Shared secret computed!")
        return shared_secret


def print_section(title):
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")

def main():
    print("\n" + "="*70)
    print("BOB'S TERMINAL - DIFFIE-HELLMAN KEY EXCHANGE")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    dh = DiffieHellman()
    
  
    print_section("STEP 1: GENERATE RSA KEYS")
    
    print("\nSelect RSA key size:")
    print("1. 2048 bits")
    print("2. 3072 bits")
    
    while True:
        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice in ['1', '2']:
            break
        print(" Invalid!")
    
    rsa_size = 2048 if choice == '1' else 3072
    bob_private_key, bob_public_key = dh.ds.generate_keys(key_size=rsa_size)
    dh.ds.display_key_info("Bob", bob_public_key)
    
    input("\n[Press Enter...]")
    
    print_section("STEP 2: READ ALICE'S DATA")
    
    filename = "alice_dh_data.txt"
    
    print(f"\nLooking for: {filename}")
    
    while not os.path.exists(filename):
        input(f" File not found. Run alice_diffie.py first, then press Enter...")
    
    print(f" File found!")
    
    with open(filename, 'r') as f:
        content = f.read()
    
    p = int(content.split("DH_PRIME:\n")[1].split("\n\n")[0])
    g = int(content.split("DH_GENERATOR:\n")[1].split("\n\n")[0])
    alice_public_value = int(content.split("ALICE_PUBLIC_VALUE:\n")[1].split("\n\n")[0])
    alice_sig_b64 = content.split("ALICE_SIGNATURE:\n")[1].split("\n\n")[0]
    alice_rsa_pem = content.split("ALICE_RSA_PUBLIC_KEY:\n")[1]
    
    alice_signature = base64.b64decode(alice_sig_b64)
    alice_public_key = serialization.load_pem_public_key(
        alice_rsa_pem.encode('utf-8'), backend=default_backend()
    )
    
    dh.set_public_parameters(p, g)
    
    print(f"Prime (p): {str(p)[:60]}...")
    print(f" Generator (g): {g}")
    print(f"Alice's g^a mod p: {str(alice_public_value)[:60]}...")
    
    input("\n[Press Enter...]")
    
    print_section("STEP 3: VERIFY ALICE'S SIGNATURE")
    
    result = dh.ds.verify_signature(str(alice_public_value), alice_signature, alice_public_key)
    
    print(f"\n{'='*70}")
    print(f"VERIFICATION RESULT: {result}")
    print(f"EXPECTED: 1")
    print(f"{'='*70}")
    
    if result == 1:
        print(" Alice's signature is valid!")
    else:
        print(" FAILED!")
        return
    
    input("\n[Press Enter...]")
    
    # STEP 4: Generate Bob's Secret
    print_section("STEP 4: BOB'S SECRET")
    
    print("\nChoose secret:")
    print("1. Auto-generate (Recommended)")
    print("2. Enter custom value")
    
    while True:
        secret_choice = input("\nEnter choice (1 or 2): ").strip()
        if secret_choice in ['1', '2']:
            break
        print(" Invalid!")
    
    if secret_choice == '1':
        bob_secret = dh.generate_secret()
        print(f"Secret (b): {str(bob_secret)[:60]}... (private!)")
    else:
        while True:
            try:
                bob_secret = int(input("\nEnter secret (b): ").strip())
                if bob_secret >= p or bob_secret < 1:
                    print(f" Must be between 1 and {p-1}")
                    continue
                print(f" Secret set")
                break
            except ValueError:
                print(" Invalid!")
    
    input("\n[Press Enter...]")
    

    print_section("STEP 5: COMPUTE PUBLIC VALUE")
    
    bob_public_value = dh.compute_public_value(bob_secret, "Bob")
    
    print(f"\n{'='*70}")
    print(f"Bob's public value (g^b mod p):")
    print(f"  {bob_public_value}")
    print(f"{'='*70}")
    
    input("\n[Press Enter...]")
    
    print_section("STEP 6: SIGN PUBLIC VALUE")
    
    bob_signature = dh.ds.sign_message(str(bob_public_value), bob_private_key)
    bob_sig_b64 = dh.ds.signature_to_base64(bob_signature)
    
    reply_filename = "bob_dh_data.txt"
    with open(reply_filename, 'w') as f:
        f.write(f"BOB_PUBLIC_VALUE:\n{bob_public_value}\n\n")
        f.write(f"BOB_SIGNATURE:\n{bob_sig_b64}\n\n")
        f.write(f"BOB_RSA_PUBLIC_KEY:\n{dh.ds.export_public_key(bob_public_key)}\n")
    
    print(f"\n Saved to: {reply_filename}")
    print(f" Go to Alice's terminal and press Enter!")
    
    input("\n[Press Enter...]")
    
    print_section("STEP 7: COMPUTE SHARED SECRET")
    
    shared_secret = dh.compute_shared_secret(alice_public_value, bob_secret, "Bob")
    
    print(f"\n{'='*70}")
    print("SHARED SECRET")
    print(f"{'='*70}")
    print(f"Bob's shared secret (K = g^ab mod p):")
    print(f"  {shared_secret}")
    print(f"{'='*70}")
    
    print_section("BOB'S SESSION COMPLETE")
    
    print(f"""
Generated RSA keys ({rsa_size} bits)
Read Alice's data from file
Alice's signature verified: {result}
Bob's g^b mod p: {str(bob_public_value)[:40]}...
Signature created and sent
Shared secret computed: {str(shared_secret)[:40]}...

 Check Alice's terminal to see if secrets match!
    """)
    
    print("="*70)
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrupted.")
