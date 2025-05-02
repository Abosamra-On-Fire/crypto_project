class LCG:
    def __init__(self, seed, a=1664525, c=1013904223, m=2**32):
        self.seed = seed
        self.a = a 
        self.c = c
        self.m = m
        
    def generate(self, length):
        keystream = bytearray()
        x = self.seed
        for _ in range(length):
            x = (self.a * x + self.c) % self.m
            keystream.append(x % 256)  # get byte value
        return bytes(keystream)
    

# test
if __name__ == "__main__":
    lcg = LCG(seed=12345)
    
    keystream = lcg.generate(20)
    print(f"Generated keystream (first 20 bytes): {keystream}")
    print(f"Hex representation: {keystream.hex()}")
    
    print("\nTesting with different seeds:")
    for seed in [1, 42, 9999]:
        lcg = LCG(seed=seed)
        print(f"Seed {seed}: {lcg.generate(10).hex()}")
    
    print("\nVerifying reproducibility:")
    lcg1 = LCG(seed=100)
    lcg2 = LCG(seed=100)
    print("Same seed produces same sequence:", lcg1.generate(10) == lcg2.generate(10))