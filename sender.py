import socket
from cryptography.hazmat.primitives.asymmetric import dh
from common import *
from stream_cipher import *
from hmac_module import *
from dh_exchange import *
def sender(): 
    '''
    Initialization: 
        Creates socket connection to receiver 
        Initializes DH key exchange as "sender" role 

    Key Exchange: 
        Preforms DH key exchange using DH_exchange 

    Encryption Setup: 
        Derives AES & HMAC keys from shared secret 
        Generates random OTP seed 
        Initializes stream cipher with seed 

    Secure Transmission: 
        Encrypts seed with AES 
        Adds HMAC authentication 
        Sends authenticated seed 

    File Processing: 
        Encrypts input.txt in 10-byte chunks 
        Streams encrypted data to receiver 
        Closes connection after completion 
    
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        try:
            dh = DH_exchange(s,'sender')
            shared_key = dh.perform_key_exchange()
            if not shared_key or not isinstance(shared_key, bytes):
                raise ValueError("wrong shared key from DH exchange")
            print(f"shared secret: {shared_key[:16].hex()}...")

            aes_key = derive_aes_key(shared_key)
            hmac_key = derive_hmac_key(shared_key)
            print(f"AES key: {aes_key.hex()[:16]}...")
            print(f"HMAC key: {hmac_key.hex()[:16]}...")

            seed = generate_random_seed()
            cipher = StreamCipher(seed)
            print(f"original  seed: {seed}")

            encrypted_seed = encrypt_seed(aes_key, seed)
            hmac_tag = HMACAuthenticator(hmac_key).generate(encrypted_seed)
            send(s, hmac_tag + encrypted_seed)
            print("sent seed")

            cipher.process_file("input.txt", "encrypted.bin")
            with open("encrypted.bin", "rb") as f:
                while chunk := f.read(10):
                    send(s, chunk)
            print("file sent successfully")

        finally:
            s.close()

if __name__ == "__main__":
    sender()
