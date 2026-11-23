from urllib.parse import urlparse


def analyze_url_features(url_result):
    findings = []
    score = 0

    url = url_result["url"]

    # IP address instead of domain
    if url_result["is_ip_address"]:
        findings.append({
            "finding": "URL uses an IP address instead of a domain",
            "score": 30
        })
        score += 30

    # Non-standard port
    port = url_result["port"]

    if port is not None and port not in [80, 443]:
        findings.append({
            "finding": f"Non-standard port detected: {port}",
            "score": 20
        })
        score += 20

    # Very long URL
    if len(url) > 150:
        findings.append({
            "finding": "Unusually long URL",
            "score": 15
        })
        score += 15

    # URL parameters
    query = urlparse(url).query

    if query:
        parameter_count = len(query.split("&"))

        if parameter_count >= 5:
            findings.append({
                "finding": "Large number of URL parameters",
                "score": 15
            })
            score += 15

    # Security-sensitive keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "password",
        "update"
    ]

    matched_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url.lower()
    ]

    if matched_keywords:
        findings.append({
            "finding": (
                "Security-sensitive keyword(s) detected: "
                + ", ".join(matched_keywords)
            ),
            "score": 10
        })
        score += 10

    return {
        "score": min(score, 100),
        "findings": findings
    }


def analyze_file_features(file_result):
    findings = []
    score = 0

    file_type = file_result["file_type"]

    if file_type == "Unknown":
        findings.append({
            "finding": "File type could not be determined",
            "score": 10
        })
        score += 10

    return {
        "score": min(score, 100),
        "findings": findings
    }
