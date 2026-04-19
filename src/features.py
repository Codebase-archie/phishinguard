import math
import sys
sys.path.append('src')
from url_parser import URLParser


def shannon_entropy(text):
    if not text:
        return 0.0
    # count frequency of each character
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    
    # compute entropy
    entropy = 0.0
    length = len(text)
    
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy
    


def extract_features(url):
    parser = URLParser(url)
    parsed = parser.parse()

    domain = parsed['domain']
    path = parsed['path']
    tld = parsed['tld']
    subdomains = parsed['subdomains']
    query = parsed['query']

    features = {
        # Length features
        'url_length': len(url),
        'domain_length': len(domain),
        'path_length': len(path),

        # Count features
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_slashes': url.count('/'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_subdomains': len(subdomains),
        'path_depth': len([p for p in path.split('/') if p]),

        # Binary features
        'has_ip': 1 if parser.is_ip_address() else 0,
        'has_at_symbol': 1 if '@' in url else 0,
        'has_double_slash': 1 if '//' in url.replace('://', '') else 0,
        'is_https': 1 if parsed['protocol'] == 'https' else 0,

        # TLD features
        'is_suspicious_tld': 1 if tld in URLParser.SUSPICIOUS_TLDS else 0,

        # Entropy features
        'url_entropy': shannon_entropy(url),
        'domain_entropy': shannon_entropy(domain),

        # Brand keyword in domain (not the actual brand site)
        'has_brand_keyword': 1 if any(
            brand in domain for brand in URLParser.BRAND_KEYWORDS
        ) else 0,

        # Ratio features
        'digit_ratio': sum(c.isdigit() for c in url) / max(len(url), 1),
        'letter_ratio': sum(c.isalpha() for c in url) / max(len(url), 1),
    }

    return features


if __name__ == "__main__":
    test_urls = [
        ("https://secure.login.paypal.com.evil.ru/account/verify?token=abc123", "phishing"),
        ("https://google.com", "benign"),
        ("http://192.168.1.1/admin/login", "phishing"),
        ("http://totally-legit-amazon-login.tk/signin", "phishing"),
        ("https://github.com/features", "benign"),
    ]

    for url, label in test_urls:
        features = extract_features(url)
        print(f"\n[{label.upper()}] {url[:60]}")
        for name, value in features.items():
            print(f"  {name}: {value}")