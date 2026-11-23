def calculate_threat_intel_score(threat_results):
    """
    Convert VirusTotal results into a score from 0 to 100.

    Unavailable results are ignored.
    """

    if not threat_results:
        return None

    scores = []

    for result in threat_results:

        status = result.get("status")

        if status == "malicious":

            malicious = result.get("malicious", 0)

            score = min(100, malicious * 10) if malicious else 70

            scores.append(score)

        elif status == "suspicious":

            suspicious = result.get("suspicious", 0)

            score = min(60, suspicious * 5) if suspicious else 30

            scores.append(score)

        elif status == "clean":

            scores.append(0)

    if not scores:
        return None

    return max(scores)


def calculate_risk_score(
    threat_intel_score=None,
    suspicious_features_score=None,
    ioc_score=None,
    analysis_score=None,
    vulnerability_score=None
):
    """
    Calculate CyberShield's overall risk score.

    Available components:
        Local analysis:       60%
        Threat intelligence:  25%
        Vulnerability score:  15%

    Unavailable components are excluded and the remaining
    weights are normalized.

    Scores must be between 0 and 100.
    """

    scores = {
        "threat_intel_score": threat_intel_score,
        "suspicious_features_score": suspicious_features_score,
        "ioc_score": ioc_score,
        "analysis_score": analysis_score,
        "vulnerability_score": vulnerability_score
    }

    # Validate scores

    for name, score in scores.items():

        if score is None:
            continue

        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ValueError(
                f"{name} must be a number or None."
            )

        if not 0 <= score <= 100:
            raise ValueError(
                f"{name} must be between 0 and 100."
            )

    # Define currently implemented components

    components = []

    if suspicious_features_score is not None:

        components.append(
            (suspicious_features_score, 0.60)
        )

    if threat_intel_score is not None:

        components.append(
            (threat_intel_score, 0.25)
        )

    if vulnerability_score is not None:

        components.append(
            (vulnerability_score, 0.15)
        )

    # No available evidence

    if not components:

        return {
            "risk_score": None,
            "severity": "Unknown",
            "components_used": [],
            "scoring_note": (
                "Insufficient evidence for risk assessment."
            )
        }

    # Normalize available weights

    total_weight = sum(
        weight for score, weight in components
    )

    risk_score = round(
        sum(
            score * weight
            for score, weight in components
        ) / total_weight
    )

    # Determine severity

    if risk_score <= 20:

        severity = "Low"

    elif risk_score <= 40:

        severity = "Medium"

    elif risk_score <= 60:

        severity = "Moderate"

    elif risk_score <= 80:

        severity = "High"

    else:

        severity = "Critical"

    # Record available components

    components_used = []

    if suspicious_features_score is not None:

        components_used.append(
            "suspicious_features_score"
        )

    if threat_intel_score is not None:

        components_used.append(
            "threat_intel_score"
        )

    if vulnerability_score is not None:

        components_used.append(
            "vulnerability_score"
        )

    # Scoring explanation

    if vulnerability_score is not None:

        scoring_note = (
            "Risk score calculated using local analysis, "
            "threat intelligence, and vulnerability evidence."
        )

    elif threat_intel_score is not None:

        scoring_note = (
            "Risk score calculated using local analysis "
            "and threat intelligence."
        )

    else:

        scoring_note = (
            "Threat intelligence unavailable; "
            "local evidence used."
        )

    return {
        "risk_score": risk_score,
        "severity": severity,
        "components_used": components_used,
        "scoring_note": scoring_note
    }
