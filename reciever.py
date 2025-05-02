import socket
from cryptography.hazmat.primitives.asymmetric import dh
from common import *
from stream_cipher import *
from hmac_module import *
from dh_exchange import DH_exchange


def reciever(): 
    '''
    Initialization: 
        Binds socket to port and listens for connection 
        Accepts sender connection 
        Initializes DH key exchange as "receiver" role 

    Key Exchange: 
        Receives DH parameters from sender 
        Preforms DH key exchange using DH_exchange 

    Authentication & Decryption: 
        Derives AES (for decryption) and HMAC keys from shared secret 
        Receives encrypted seed + HMAC tag 
        Verifies HMAC to ensure integrity 
        Decrypts seed using AES 

    File Processing: 
        Initializes stream cipher with decrypted seed 
        Receives encrypted file chunks 
        Decrypts each chunk using OTP keystream 
        Writes decrypted data to output.txt 

    Completion: 
        Closes connection 
        Verifies output.txt matches sender's original file 
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("yatem estema3")
        conn, addr = s.accept()
        try:
            with conn:
                dh = DH_exchange(conn, "reciever")
                shared_key = dh.perform_key_exchange()
                if not shared_key or not isinstance(shared_key, bytes):
                    raise ValueError("worng shared key from DH exchange")
                print(f"shared key: {shared_key[:16].hex()}...")

                aes_key = derive_aes_key(shared_key)
                hmac_key = derive_hmac_key(shared_key)
                print(f"AES key: {aes_key.hex()[:16]}...")
                print(f"HMAC key: {hmac_key.hex()[:16]}...")

                auth_data = recv(conn)
                if not auth_data or len(auth_data) < 32:
                    raise ValueError("wrong recived data")
                
                hmac_tag = auth_data[:32]
                encrypted_seed = auth_data[32:]
                
                if not HMACAuthenticator(hmac_key).verify(encrypted_seed, hmac_tag):
                    raise ValueError("HMAC failed!")
                print("seed recieved successful")

                seed = decrypt_seed(aes_key, encrypted_seed)
                print(f"seed: {seed}")

                cipher = StreamCipher(seed)

                with open("output.txt", "wb") as f:
                    while True:
                        chunk = recv(conn)
                        if not chunk:
                            break
                        decrypted = cipher.process_chunk(chunk)
                        f.write(decrypted)
                print("file received successfully")
        finally:
            conn.close()
            s.close()
        
if __name__ == "__main__":
    reciever()