import hashlib


class BloomFilter:

    def __init__(self, size=1_000_000, num_hashes=3):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray(size)

    def _hash(self, item, seed):
        combined = f"{item}:{seed}".encode()
        hash_digest = hashlib.md5(combined).hexdigest()
        hash_int = int(hash_digest, 16)
        return hash_int % self.size
        

    def add(self, item):
        for i in range(self.num_hashes):
            index = self._hash(item, i)
            self.bit_array[index] = 1
        

    def might_contain(self, item):
        for i in range(self.num_hashes):
            index = self._hash(item, i)
            if self.bit_array[index] == 0:
                return False
        return True
       

    def load_from_list(self, items):
        for item in items:
            self.add(item)
        


if __name__ == "__main__":
    bf = BloomFilter()

    print("\n=== Loading real benign domains from Tranco ===")
    import pandas as pd

    tranco = pd.read_csv('data/tranco.csv', header=None, names=['rank', 'domain'])
    top_domains = tranco['domain'].head(100_000).tolist()

    print(f"Loading {len(top_domains)} domains into Bloom filter...")
    bf2 = BloomFilter(size=5_000_000, num_hashes=3)
    bf2.load_from_list(top_domains)

    print("\nTesting against real domains:")
    real_tests = [
        "google.com",
        "youtube.com",
        "evil-phishing-site.tk",
        "paypal.com.hackers.ru",
        "nobell.it",
    ]
    for domain in real_tests:
        print(f"  {domain}: {bf2.might_contain(domain)}")