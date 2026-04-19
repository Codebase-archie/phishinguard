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

    benign_domains = ["google.com", "facebook.com", "amazon.com",
                      "youtube.com", "twitter.com", "github.com"]

    print("Loading benign domains...")
    bf.load_from_list(benign_domains)

    print("\n=== Testing ===")
    test_cases = [
        ("google.com", "should be True"),
        ("github.com", "should be True"),
        ("evil-phishing.tk", "should be False"),
        ("paypal.com.evil.ru", "should be False"),
        ("amazon.com", "should be True"),
    ]

    for domain, expected in test_cases:
        result = bf.might_contain(domain)
        status = "PASS" if (result == ("True" in expected)) else "FAIL"
        print(f"[{status}] {domain}: {result} ({expected})")