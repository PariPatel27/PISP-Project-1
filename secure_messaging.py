from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import os


class SecureMessaging:
    
    def __init__(self):
        self.backend = default_backend()
    
    # Symmetric Encryption
    def sym_enc(self, plaintext, key, iv, mode='CBC'):
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Encrypting message...")
        print(f"  Mode: AES-{mode}")
        print(f"  Key length: {len(key)} bytes ({len(key)*8} bits)")
        print(f"  IV length: {len(iv)} bytes")
        
        # Convert plaintext to bytes
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        print(f"  Plaintext length: {len(plaintext_bytes)} bytes")
        
        # Padding for CBC mode (AES block size = 16 bytes)
        if mode == 'CBC':
            padding_length = 16 - (len(plaintext_bytes) % 16)
            plaintext_bytes += bytes([padding_length] * padding_length)
            print(f"  Padded length: {len(plaintext_bytes)} bytes")
        
        # Create cipher
        if mode == 'CBC':
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
        elif mode == 'CTR':
            # CTR mode uses IV as nonce
            cipher = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=self.backend
            )
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        
        # Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Encryption complete!")
        print(f"  Ciphertext length: {len(ciphertext)} bytes")
        
        return ciphertext
    
        #Symmetric decryption function.
    def sym_dec(self, ciphertext, key, iv, mode='CBC'):
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Decrypting message...")
        print(f"  Mode: AES-{mode}")
        print(f"  Ciphertext length: {len(ciphertext)} bytes")
        
        # Create cipher
        if mode == 'CBC':
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
        elif mode == 'CTR':
            cipher = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=self.backend
            )
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        
        # Decrypt
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding for CBC mode
        if mode == 'CBC':
            padding_length = plaintext_bytes[-1]
            plaintext_bytes = plaintext_bytes[:-padding_length]
        
        # Convert to string
        plaintext = plaintext_bytes.decode('utf-8')
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Decryption complete!")
        print(f"  Plaintext length: {len(plaintext_bytes)} bytes")
        
        return plaintext
    
    #HMAC Functions
    def compute_hmac(self, message, key):
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Computing HMAC...")
        print(f"  Message length: {len(message)} bytes")
        print(f"  Key length: {len(key)} bytes")
        
        # Create HMAC - 256
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        hmac_value = h.finalize()
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  HMAC computed!")
        print(f"  HMAC length: {len(hmac_value)} bytes ({len(hmac_value)*8} bits)")
        
        return hmac_value
    
    def verify_hmac(self, message, key, received_hmac):
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Verifying HMAC...")
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(message)
        
        try:
            h.verify(received_hmac)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HMAC is VALID ")
            return True
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HMAC is INVALID ")
            print(f"  Reason: Message may be tampered!")
            return False
    
    #Encrypt then MAC
    def authenticated_encrypt(self, plaintext, encryption_key, hmac_key, iv, mode='CBC'):
        
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting Authenticated Encryption...")
        print(f"  Scheme: Encrypt-then-MAC")
        
        # Step 1: Encrypt
        print(f"\n  STEP 1: Symmetric Encryption")
        ciphertext = self.sym_enc(plaintext, encryption_key, iv, mode)
        
        # Step 2: Compute HMAC on ciphertext
        print(f"\n  STEP 2: Compute HMAC on Ciphertext")
        mac = self.compute_hmac(ciphertext, hmac_key)
        
        # Step 3: Combine ciphertext and MAC
        combined = ciphertext + mac
        
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✓ Authenticated Encryption complete!")
        print(f"  Ciphertext: {len(ciphertext)} bytes")
        print(f"  HMAC: {len(mac)} bytes")
        print(f"  Combined output: {len(combined)} bytes")
        
        return {
            'ciphertext': ciphertext,
            'hmac': mac,
            'combined': combined,
            'iv': iv,
            'mode': mode
        }
    
    def authenticated_decrypt(self, combined_data, encryption_key, hmac_key, iv, mode='CBC'):
        
       # Decrypt and verify authenticated ciphertext
        
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting Authenticated Decryption...")
        print(f"  Scheme: Encrypt-then-MAC")
        print(f"  Combined data length: {len(combined_data)} bytes")
        
        # Step 1: Split ciphertext and HMAC
        # HMAC-SHA256 is always 32 bytes
        hmac_size = 32
        ciphertext = combined_data[:-hmac_size]
        received_hmac = combined_data[-hmac_size:]
        
        print(f"\n  STEP 1: Split Data")
        print(f"    Ciphertext: {len(ciphertext)} bytes")
        print(f"    HMAC: {len(received_hmac)} bytes")
        
        # Step 2: Verify HMAC
        print(f"\n  STEP 2: Verify HMAC")
        is_valid = self.verify_hmac(ciphertext, hmac_key, received_hmac)
        
        if not is_valid:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Authentication failed!")
            print(f"  Message may be tampered or corrupted!")
            print(f"  Decryption ABORTED for security!")
            return None
        
        print(f"   HMAC verified! Message is authentic.")
        
        # Step 3: Decrypt
        print(f"\n  STEP 3: Decrypt Ciphertext")
        plaintext = self.sym_dec(ciphertext, encryption_key, iv, mode)
        
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]  Authenticated Decryption complete!")
        print(f"  Message successfully decrypted and verified!")
        
        return plaintext


def print_section(title):
#print title
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")


def bytes_to_hex(data, max_length=64):
#convert bytes to hex
    hex_str = data.hex()
    if len(hex_str) > max_length:
        return hex_str[:max_length] + "..."
    return hex_str
