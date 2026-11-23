import re
import ipaddress
from urllib.parse import urlsplit


def extract_iocs(text):
    iocs = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }

    if not text:
        return iocs

    def add_unique(category, value):
        if value and value not in iocs[category]:
            iocs[category].append(value)

    # 1. Extract and validate URLs
    url_pattern = r'https?://[^\s\'"]+'
    potential_urls = re.findall(url_pattern, text)

    for raw_url in potential_urls:
        url = raw_url.rstrip(".,;:!?)\"]}")

        if not url:
            continue

        add_unique("urls", url)

        try:
            parsed = urlsplit(url)
            host = parsed.hostname

            if not host:
                continue

            # Classify URL host as IP or domain
            try:
                ip = ipaddress.ip_address(host)
                add_unique("ip_addresses", str(ip))
            except ValueError:
                add_unique("domains", host.lower())

        except ValueError:
            continue

    # 2. Extract standalone IPv4 addresses
    potential_ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        text
    )

    for value in potential_ips:
        try:
            ip = ipaddress.ip_address(value)
            add_unique("ip_addresses", str(ip))
        except ValueError:
            continue

    # 3. Extract common hash formats
    hash_pattern = (
        r'\b[a-fA-F0-9]{32}\b|'
        r'\b[a-fA-F0-9]{40}\b|'
        r'\b[a-fA-F0-9]{64}\b'
    )

    for hash_value in re.findall(hash_pattern, text):
        add_unique("hashes", hash_value.lower())

    # 4. Extract domain-like strings
    domain_pattern = (
        r'\b(?:[a-zA-Z0-9-]+\.)+'
        r'[a-zA-Z]{2,}\b'
    )

    for domain in re.findall(domain_pattern, text):
        domain = domain.lower()

        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass

        add_unique("domains", domain)

    return iocs
