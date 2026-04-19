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
    

def min_edit_distance_to_brand(domain):
    """
    Returns the minimum edit distance ratio between
    the domain and any known brand domain.
    Ratio of 1.0 means identical, 0.0 means completely different.
    """
    brands = [
        'paypal.com', 'google.com', 'facebook.com', 'amazon.com',
        'apple.com', 'netflix.com', 'microsoft.com', 'instagram.com',
        'twitter.com', 'linkedin.com', 'bankofamerica.com', 'chase.com'
    ]

    if not domain:
        return 0.0

    max_ratio = 0.0
    domain_len = len(domain)

    for brand in brands:
        brand_len = len(brand)

        # build edit distance matrix
        dp = [[0] * (brand_len + 1) for _ in range(domain_len + 1)]

        for i in range(domain_len + 1):
            dp[i][0] = i
        for j in range(brand_len + 1):
            dp[0][j] = j

        for i in range(1, domain_len + 1):
            for j in range(1, brand_len + 1):
                if domain[i-1] == brand[j-1]:
                    dp[i][j] = dp[i-1][j-1]
                else:
                    dp[i][j] = 1 + min(
                        dp[i-1][j],    # delete
                        dp[i][j-1],    # insert
                        dp[i-1][j-1]   # replace
                    )

        edit_dist = dp[domain_len][brand_len]
        max_possible = max(domain_len, brand_len)
        ratio = 1 - (edit_dist / max_possible)
        max_ratio = max(max_ratio, ratio)

    return round(max_ratio, 4)

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
        
        # Additional strong signals
        'query_length': len(query),
        'num_params': query.count('&') + 1 if query else 0,
        'has_hex_chars': 1 if '%' in url else 0,
        'consonant_ratio': sum(
            c in 'bcdfghjklmnpqrstvwxyz' for c in domain
        ) / max(len(domain), 1),
        'domain_has_digits': 1 if any(c.isdigit() for c in domain) else 0,
        
        'brand_similarity': min_edit_distance_to_brand(domain),
        
        'special_char_count': sum(
            c in '!@#$%^&*()+=[]{}|;:,<>?' for c in url
        ),
        'repeated_digits': max(
            [len(s) for s in __import__('re').findall(r'\d+', url)] or [0]
        ),
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