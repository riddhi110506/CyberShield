import re
import ipaddress
from urllib.parse import urlsplit


def extract_strings(file_path, min_length=4):
    """
    Extract readable ASCII strings from a file.
    The file is only read; it is never executed.
    """

    strings = []

    try:
        with open(file_path, "rb") as file:
            data = file.read()

        pattern = rb"[ -~]{" + str(min_length).encode() + rb",}"
        matches = re.findall(pattern, data)

        for match in matches:
            strings.append(match.decode("ascii", errors="ignore"))

    except OSError:
        return []

    return strings


def analyze_static_file(file_path):
    """
    Perform safe static analysis on a file.
    The file is never executed.
    """

    strings = extract_strings(file_path)

    urls = []
    ip_addresses = []
    domains = []
    suspicious_terms = []

    url_pattern = r"https?://[^\s\"'<>]+"

    ip_pattern = (
        r"\b(?:"
        r"25[0-5]|2[0-4][0-9]|"
        r"1?[0-9]{1,2}"
        r")"
        r"(?:\."
        r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
        r"){3}\b"
    )

    domain_pattern = (
        r"(?<![@\w.-])"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}"
        r"(?![\w.-])"
    )

    suspicious_keywords = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "schtasks",
        "certutil",
        "bitsadmin"
    ]

    for string in strings:

        # Extract URLs
        found_urls = re.findall(url_pattern, string)

        for url in found_urls:
            url = url.rstrip(".,;:!?)\"]}")

            if url not in urls:
                urls.append(url)

            # Extract domain or IP from URL
            try:
                hostname = urlsplit(url).hostname

                if hostname:
                    try:
                        ipaddress.ip_address(hostname)

                        if hostname not in ip_addresses:
                            ip_addresses.append(hostname)

                    except ValueError:
                        hostname = hostname.lower()

                        if hostname not in domains:
                            domains.append(hostname)

            except ValueError:
                pass

        # Extract standalone IP addresses
        found_ips = re.findall(ip_pattern, string)

        for ip in found_ips:
            try:
                ipaddress.ip_address(ip)

                if ip not in ip_addresses:
                    ip_addresses.append(ip)

            except ValueError:
                pass

        # Extract standalone domains
        found_domains = re.findall(domain_pattern, string)

        for domain in found_domains:
            domain = domain.lower()

            # Ignore common executable and file extensions.
            file_extensions = {
                "exe", "dll", "sys", "bat", "cmd",
                "ps1", "vbs", "scr", "msi", "bin",
                "txt", "log", "json", "xml"
            }

            if domain.rsplit(".", 1)[-1] in file_extensions:
                continue

            try:
                ipaddress.ip_address(domain)
                continue
            except ValueError:
                pass

            if domain not in domains:
                domains.append(domain)

        # Detect suspicious command/tool references
        lower_string = string.lower()

        for keyword in suspicious_keywords:
            if keyword in lower_string:
                if keyword not in suspicious_terms:
                    suspicious_terms.append(keyword)

    return {
        "strings_count": len(strings),
        "urls": urls,
        "ip_addresses": ip_addresses,
        "domains": domains,
        "suspicious_terms": suspicious_terms
    }
