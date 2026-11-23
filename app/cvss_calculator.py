# app/cvss_calculator.py

import math


# CVSS v3.1 metric weights

AV_VALUES = {
    "N": 0.85,
    "A": 0.62,
    "L": 0.55,
    "P": 0.20
}

AC_VALUES = {
    "L": 0.77,
    "H": 0.44
}

UI_VALUES = {
    "N": 0.85,
    "R": 0.62
}

CIA_VALUES = {
    "H": 0.56,
    "L": 0.22,
    "N": 0.0
}

PR_VALUES = {
    "U": {
        "N": 0.85,
        "L": 0.62,
        "H": 0.27
    },
    "C": {
        "N": 0.85,
        "L": 0.68,
        "H": 0.50
    }
}


def round_up(value):
    """
    CVSS rounding method.

    CVSS scores are rounded upward to one decimal place.
    """

    return math.ceil(value * 10 - 1e-10) / 10


def calculate_severity(score):
    """
    Determine CVSS severity from score.
    """

    if score == 0:
        return "None"

    elif score <= 3.9:
        return "Low"

    elif score <= 6.9:
        return "Medium"

    elif score <= 8.9:
        return "High"

    else:
        return "Critical"


def calculate_cvss_v3_1(
    attack_vector,
    attack_complexity,
    privileges_required,
    user_interaction,
    scope,
    confidentiality,
    integrity,
    availability
):
    """
    Calculate CVSS v3.1 Base Score.

    Parameters:
        attack_vector: N, A, L, P
        attack_complexity: L, H
        privileges_required: N, L, H
        user_interaction: N, R
        scope: U, C
        confidentiality: H, L, N
        integrity: H, L, N
        availability: H, L, N

    Returns:
        Dictionary containing CVSS score, severity and vector.
    """

    attack_vector = attack_vector.upper()
    attack_complexity = attack_complexity.upper()
    privileges_required = privileges_required.upper()
    user_interaction = user_interaction.upper()
    scope = scope.upper()

    confidentiality = confidentiality.upper()
    integrity = integrity.upper()
    availability = availability.upper()

    # Validate metrics

    if attack_vector not in AV_VALUES:
        raise ValueError("Invalid Attack Vector")

    if attack_complexity not in AC_VALUES:
        raise ValueError("Invalid Attack Complexity")

    if privileges_required not in PR_VALUES[scope]:
        raise ValueError("Invalid Privileges Required")

    if user_interaction not in UI_VALUES:
        raise ValueError("Invalid User Interaction")

    if scope not in PR_VALUES:
        raise ValueError("Invalid Scope")

    if confidentiality not in CIA_VALUES:
        raise ValueError("Invalid Confidentiality")

    if integrity not in CIA_VALUES:
        raise ValueError("Invalid Integrity")

    if availability not in CIA_VALUES:
        raise ValueError("Invalid Availability")

    # --------------------------------------------------
    # Exploitability
    # --------------------------------------------------

    exploitability = (
        8.22
        * AV_VALUES[attack_vector]
        * AC_VALUES[attack_complexity]
        * PR_VALUES[scope][privileges_required]
        * UI_VALUES[user_interaction]
    )

    # --------------------------------------------------
    # Impact
    # --------------------------------------------------

    impact_sub_score = 1 - (
        (1 - CIA_VALUES[confidentiality])
        * (1 - CIA_VALUES[integrity])
        * (1 - CIA_VALUES[availability])
    )

    if scope == "U":

        impact = 6.42 * impact_sub_score

    else:

        impact = (
            7.52 * (impact_sub_score - 0.029)
            - 3.25 * (impact_sub_score - 0.02) ** 15
        )

    # --------------------------------------------------
    # Base Score
    # --------------------------------------------------

    if impact <= 0:

        base_score = 0.0

    elif scope == "U":

        base_score = round_up(
            min(impact + exploitability, 10)
        )

    else:

        base_score = round_up(
            min(1.08 * (impact + exploitability), 10)
        )

    severity = calculate_severity(base_score)

    # --------------------------------------------------
    # CVSS Vector
    # --------------------------------------------------

    vector = (
        f"CVSS:3.1/"
        f"AV:{attack_vector}/"
        f"AC:{attack_complexity}/"
        f"PR:{privileges_required}/"
        f"UI:{user_interaction}/"
        f"S:{scope}/"
        f"C:{confidentiality}/"
        f"I:{integrity}/"
        f"A:{availability}"
    )

    return {
        "cvss_version": "3.1",
        "cvss_score": base_score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "exploitability_score": round(exploitability, 2),
        "impact_score": round(impact, 2)
    }
