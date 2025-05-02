import socket
from cryptography.hazmat.primitives.asymmetric import dh
from common import *
from stream_cipher import *
from hmac_module import *
from dh_exchange import DH_exchange
def sender(): 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        try:

            shared_key = DH_exchange(s, "sender")
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
