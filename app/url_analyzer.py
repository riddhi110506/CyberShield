from urllib.parse import urlparse
import ipaddress


def analyze_url(url):
    url = url.strip()

    if not url:
        return None

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return None

    hostname = parsed.hostname

    if not hostname:
        return None

    is_ip = False

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "is_ip_address": is_ip
    }
