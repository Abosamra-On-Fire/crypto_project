import os
import struct
from typing import Optional
from lcg import LCG

class StreamCipher:
    CHUNK_SIZE = 10  

    def __init__(self, seed: Optional[int] = None):
        self.seed = int.from_bytes(seed, 'big') if seed is not None else self._generate_seed()
        self.lcg = LCG(self.seed)

    def _generate_seed(self) -> int:
        return struct.unpack('Q', os.urandom(32))[0] 

    def process_chunk(self, data: bytes) -> bytes:
        keystream = self.lcg.generate(len(data))
        return bytes([d ^ k for d, k in zip(data, keystream)])

    def process_file(self, input_path: str, output_path: str) -> None:
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            while True:
                chunk = fin.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                processed = self.process_chunk(chunk)
                fout.write(processed)

    @property
    def seed(self) -> int:
        return self._seed

    @seed.setter
    def seed(self, value: int) -> None:
        self._seed = value
        self.lcg = LCG(value)



def main(): #test
    print("=== Stream Cipher Implementation Test ===")
    print("Testing with sample text file...")
    
    test_content = b"This is a test message for the stream cipher implementation. 1234567890!"
    with open('test_input.txt', 'wb') as f:
        f.write(test_content)
    
    print("\n[SENDER] Encrypting file...")
    sender = StreamCipher()
    sender.process_file('test_input.txt', 'encrypted.bin')
    print(f"Generated seed: {sender.seed}")
    
    print("\n[RECEIVER] Decrypting file...")
    receiver = StreamCipher(sender.seed) 
    receiver.process_file('encrypted.bin', 'decrypted.txt')
    
    with open('decrypted.txt', 'rb') as f:
        decrypted_content = f.read()
    
    print("\n[VERIFICATION]")
    print(f"Original length: {len(test_content)} bytes")
    print(f"Decrypted length: {len(decrypted_content)} bytes")
    print(f"First 20 bytes match: {test_content[:20] == decrypted_content[:20]}")
    print(f"Complete match: {test_content == decrypted_content}")
    
    print("\n[CHUNK PROCESSING DEMO]")
    print("Showing first 3 chunks processed:")
    cipher = StreamCipher()
    with open('test_input.txt', 'rb') as f:
        for i in range(3):
            chunk = f.read(10)
            if not chunk:
                break
            encrypted = cipher.process_chunk(chunk)
            decrypted = cipher.process_chunk(encrypted)
            print(f"Chunk {i+1}: Original: {chunk} | Encrypted: {encrypted} | Decrypted: {decrypted}")
    
    for f in ['test_input.txt', 'encrypted.bin', 'decrypted.txt']:
        if os.path.exists(f):
            os.remove(f)
    print("\nTest files cleaned up.")

if __name__ == "__main__":
    main()