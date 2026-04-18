class URLParser:

    SUSPICIOUS_TLDS = ['.ru', '.tk', '.pw', '.cc', '.zip', '.xyz', '.top', '.work']
    BRAND_KEYWORDS = ['paypal', 'amazon', 'google', 'facebook', 'apple', 'netflix', 'bank']

    def __init__(self, url):
        self.url = url.lower().strip().strip("'")

    def is_ip_address(self):
        domain = self.get_domain()
        parts = domain.split(".")
        if len(parts) == 4:
            return all(part.isdigit() for part in parts)
        return False

    def get_protocol(self):
        parts = self.url.split("://")
        if len(parts) > 1:
            return parts[0]
        return "unknown"

    def get_domain(self):
        parts = self.url.split("://")
        rest = parts[1] if len(parts) > 1 else self.url
        domain = rest.split("/")[0]
        return domain

    def get_tld(self):
        if self.is_ip_address():
            return "ip"
        domain = self.get_domain()
        tld_parts = domain.split(".")
        if len(tld_parts) > 1:
            return "." + tld_parts[-1]
        return "unknown"

    def get_subdomains(self):
        if self.is_ip_address():
            return []
        domain = self.get_domain()
        domain_parts = domain.split(".")
        if len(domain_parts) > 2:
            return domain_parts[:-2]
        return []

    def get_path(self):
        parts = self.url.split("://")
        rest = parts[1] if len(parts) > 1 else self.url
        path_parts = rest.split("/", 1)
        if len(path_parts) > 1:
            path = path_parts[1]
            path = path.split("?")[0]
            path = path.split("#")[0]
            return path
        return ""

    def get_query_params(self):
        if "?" not in self.url:
            return ""
        query = self.url.split("?", 1)[1]
        query = query.split("#")[0]
        return query

    def parse(self):
        return {
            "url": self.url,
            "protocol": self.get_protocol(),
            "domain": self.get_domain(),
            "tld": self.get_tld(),
            "subdomains": self.get_subdomains(),
            "path": self.get_path(),
            "query": self.get_query_params(),
        }


if __name__ == "__main__":
    test_urls = [
        "https://secure.login.paypal.com.evil.ru/account/verify?token=abc123",
        "http://192.168.1.1/admin",
        "https://google.com",
        "http://totally-legit-amazon-login.tk/signin",
    ]

    for url in test_urls:
        result = URLParser(url).parse()
        print(result)
        print("---")