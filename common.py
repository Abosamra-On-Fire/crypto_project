import struct
from cryptography.hazmat.primitives import serialization ,padding,hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

HOST = "127.0.0.1"
PORT = 5353
key_size = 512

def send(s, data):
    if isinstance(data, str):
        data = data.encode()
    data = struct.pack('>I', len(data)) + data
    s.sendall(data)

def recv(s):
    raw_msglen = recvall(s, 4) # 4 bytes matensash!!
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    msg = recvall(s, msglen)
    return msg

def recvall(s, n):    
    data = bytearray()
    while len(data) < n:    
        packet = s.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def ser_public_key(sender_public_key):
    return sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deser_public_key(ser_public_key):
    return serialization.load_pem_public_key(ser_public_key)

def generate_random_seed(seed_length=32):
    return os.urandom(seed_length)

def derive_aes_key(shared_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'aes_key_derivation'
    )
    return hkdf.derive(shared_key)

def derive_hmac_key(shared_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hmac_key_derivation'
    )
    return hkdf.derive(shared_key)

def encrypt_seed(shared_key, seed):
    aes_key = derive_aes_key(shared_key)
    iv = os.urandom(16)  
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(seed) + padder.finalize()
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    )
    encryptor = cipher.encryptor()
    seed_ = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + seed_ 

def decrypt_seed(shared_key, encrypted_data):
    aes_key = derive_aes_key(shared_key)
    iv = encrypted_data[:16]
    seed_ = encrypted_data[16:]
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    )
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(seed_) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()