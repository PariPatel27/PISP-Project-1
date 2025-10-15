from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime


class DigitalSignature:
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_keys(self, key_size=2048):
        # will generate public key and private key in form of tuple.
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Generating RSA key pair ({key_size} bits)...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # generate public key from private key
        public_key = private_key.public_key()
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Key pair generated successfully!")
        
        return private_key, public_key
    
    def hash_message(self, message):
        #will apply hash SHA-256 to message
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(message)
        hash_value = digest.finalize()
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Message hashed using SHA-256")
        print(f"  Hash (hex): {hash_value.hex()[:64]}...")
        
        return hash_value
    
    def sign_message(self, message, private_key):
        #it will sign a message on hashed message
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signing message with private key...")
        
        # Signing the message using PSS padding and SHA-256
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signature created successfully!")
        
        return signature
    
    def verify_signature(self, message, signature, public_key):
        #it will verify the message and will return 1 for valid and 0 for invalid
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Verifying signature")
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signature is VALID")
            return 1
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Signature is INVALID")
            return 0
    
    def export_public_key(self, public_key):
        #generating public key in Privacy-Enhanced Mail format
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def import_public_key(self, pem_string):
        #importing public key
        if isinstance(pem_string, str):
            pem_string = pem_string.encode('utf-8')
        
        public_key = serialization.load_pem_public_key(
            pem_string,
            backend=self.backend
        )
        return public_key
    
    def signature_to_base64(self, signature):
        #convert signature to string in readable format
        return base64.b64encode(signature).decode('utf-8')
    
    def base64_to_signature(self, base64_string):
        #convert string in readable format to signature
        return base64.b64decode(base64_string)
    
    def get_key_info(self, public_key):
        #get information about public key
        key_numbers = public_key.public_numbers()
        return {
            'modulus': key_numbers.n,
            'exponent': key_numbers.e,
            'key_size': public_key.key_size
        }
    
    def display_key_info(self, name, public_key):
        #display information about public key
        print(f"\n{'='*70}")
        print(f"{name}'s Public Key Information")
        print(f"{'='*70}")
        
        key_info = self.get_key_info(public_key)
        print(f"Key Size: {key_info['key_size']} bits")
        print(f"Public Exponent (e): {key_info['exponent']}")
        print(f"Modulus (n): {str(key_info['modulus'])[:60]}...")
        print(f"\nPEM Format (for sharing):")
        print("-" * 70)
        print(self.export_public_key(public_key))


def print_section(title):
    #print title
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")