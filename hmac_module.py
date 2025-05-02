import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class HMACAuthenticator:
    KEY_SIZE = 32  # 256-bit

    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(self.KEY_SIZE)
        if len(self.key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")

    def generate(self, message: bytes) -> bytes:
        """returns HMAC digest"""
        return hmac.new(self.key, message, hashlib.sha256).digest()

    def verify(self, message: bytes, received_digest: bytes) -> bool:
        """Safe comparison"""
        expected_digest = self.generate(message)
        return hmac.compare_digest(expected_digest, received_digest)
    
        
def test_hmac_authentication():# fro testing
    print("\n=== Testing HMAC Authentication ===")
    authenticator = HMACAuthenticator()
    test_message = b"Important data for HMAC verification"
    
    digest = authenticator.generate(test_message)
    print(f"HMAC Digest: {digest.hex()}")
    verification = authenticator.verify(test_message, digest)
    print(f"Test {'PASSED' if verification else 'FAILED'} - Correct HMAC verification")
    
    tampered_msg = test_message + b" "
    verification = authenticator.verify(tampered_msg, digest)
    print(f"Test {'PASSED' if not verification else 'FAILED'} - Tamper detection")
    
    wrong_authenticator = HMACAuthenticator()
    verification = wrong_authenticator.verify(test_message, digest)
    print(f"Test {'PASSED' if not verification else 'FAILED'} - Wrong key rejection")

def main(): # test
    print("=== Cryptographic Components Test ===")
 
    test_hmac_authentication()
 

if __name__ == "__main__":
    main()