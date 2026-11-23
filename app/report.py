from datetime import datetime


def generate_report(
    input_type,
    input_value,
    analysis_result,
    iocs,
    threat_intel,
    risk_result,
    vulnerability,
    mitre_results,
    feature_result,
    static_result=None,
    elastic_results=None,
):

    report = []

    # =========================================================
    # ANALYSIS SUMMARY
    # =========================================================

    report.append("=" * 70)

    report.append(
        "CYBERSHIELD - THREAT ANALYSIS AND RISK ASSESSMENT REPORT"
    )

    report.append("=" * 70)

    report.append(
        f"Generated At: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    report.append(
        f"Analysis Type: {input_type}"
    )

    report.append(
        f"Input: {input_value}"
    )

    report.append("-" * 70)

    report.append(
        "ANALYSIS SUMMARY"
    )

    report.append("-" * 70)

    if isinstance(
        analysis_result,
        dict
    ):

        for key, value in analysis_result.items():

            report.append(
                f"{key.replace('_', ' ').title()}: {value}"
            )

    else:

        report.append(
            str(analysis_result)
        )

    # =========================================================
    # STATIC ANALYSIS
    # =========================================================

    report.append("")
    report.append("-" * 70)
    report.append("STATIC ANALYSIS")
    report.append("-" * 70)

    if static_result:

        if isinstance(
            static_result,
            dict
        ):

            for key, value in static_result.items():

                report.append(
                    f"{key.replace('_', ' ').title()}: {value}"
                )

        else:

            report.append(
                str(static_result)
            )

    else:

        report.append(
            "Static analysis information unavailable."
        )

    # =========================================================
    # INDICATORS OF COMPROMISE
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "INDICATORS OF COMPROMISE (IOCs)"
    )

    report.append("-" * 70)

    if iocs:

        if isinstance(
            iocs,
            dict
        ):

            for category, values in iocs.items():

                report.append("")

                report.append(
                    f"{category.upper().replace('_', ' ')}:"
                )

                if isinstance(
                    values,
                    list
                ):

                    if values:

                        for value in values:

                            report.append(
                                f"  - {value}"
                            )

                    else:

                        report.append(
                            "  None detected"
                        )

                else:

                    report.append(
                        f"  {values}"
                    )

        elif isinstance(
            iocs,
            list
        ):

            for ioc in iocs:

                report.append(
                    f"  - {ioc}"
                )

        else:

            report.append(
                str(iocs)
            )

    else:

        report.append(
            "No indicators of compromise identified."
        )

    # =========================================================
    # THREAT INTELLIGENCE
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "THREAT INTELLIGENCE"
    )

    report.append("-" * 70)

    if threat_intel:

        if isinstance(
            threat_intel,
            dict
        ):

            for key, value in threat_intel.items():

                report.append(
                    f"{key.replace('_', ' ').title()}: {value}"
                )

        else:

            for result in threat_intel:

                if isinstance(
                    result,
                    dict
                ):

                    for key, value in result.items():

                        report.append(
                            f"{key.replace('_', ' ').title()}: {value}"
                        )

                    report.append("")

                else:

                    report.append(
                        str(result)
                    )

    else:

        report.append(
            "Threat intelligence information unavailable."
        )

    # =========================================================
    # RISK ASSESSMENT
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "RISK ASSESSMENT"
    )

    report.append("-" * 70)

    if risk_result:

        if isinstance(
            risk_result,
            dict
        ):

            for key, value in risk_result.items():

                report.append(
                    f"{key.replace('_', ' ').title()}: {value}"
                )

        else:

            report.append(
                str(risk_result)
            )

    else:

        report.append(
            "Risk assessment information unavailable."
        )

    # =========================================================
    # RISK EVIDENCE
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "RISK EVIDENCE"
    )

    report.append("-" * 70)

    if feature_result:

        if isinstance(
            feature_result,
            dict
        ):

            for key, value in feature_result.items():

                report.append(
                    f"{key.replace('_', ' ').title()}: {value}"
                )

        else:

            report.append(
                str(feature_result)
            )

    else:

        report.append(
            "No additional risk evidence available."
        )

    # =========================================================
    # VULNERABILITY ASSESSMENT / CVSS
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "VULNERABILITY ASSESSMENT / CVSS"
    )

    report.append("-" * 70)

    if (
        vulnerability
        and isinstance(
            vulnerability,
            dict
        )
    ):

        vulnerability_found = vulnerability.get(
            "vulnerability_found",
            False
        )

        report.append(
            f"Vulnerability Found: {vulnerability_found}"
        )

        # CVE ID

        cve_id = vulnerability.get(
            "cve_id"
        )

        if cve_id:

            report.append(
                f"CVE ID: {cve_id}"
            )

        # Description

        description = vulnerability.get(
            "description"
        )

        if description:

            report.append("")
            report.append(
                "Description:"
            )

            report.append(
                str(description)
            )

        # CVSS Version

        cvss_version = vulnerability.get(
            "cvss_version"
        )

        if cvss_version:

            report.append(
                f"CVSS Version: {cvss_version}"
            )

        # CVSS Score

        cvss_score = vulnerability.get(
            "cvss_score"
        )

        if cvss_score is not None:

            report.append(
                f"CVSS Score: {cvss_score}/10"
            )

        # Severity

        severity = vulnerability.get(
            "cvss_severity"
        )

        if severity:

            report.append(
                f"Severity: {severity}"
            )

        # CVSS Vector

        cvss_vector = vulnerability.get(
            "cvss_vector"
        )

        if cvss_vector:

            report.append(
                f"CVSS Vector: {cvss_vector}"
            )

        # CWE

        cwe_id = vulnerability.get(
            "cwe_id"
        )

        if cwe_id:

            report.append(
                f"CWE ID: {cwe_id}"
            )

        # Exploitability Score

        exploitability_score = vulnerability.get(
            "exploitability_score"
        )

        if exploitability_score is not None:

            report.append(
                f"Exploitability Score: "
                f"{exploitability_score}"
            )

        # Impact Score

        impact_score = vulnerability.get(
            "impact_score"
        )

        if impact_score is not None:

            report.append(
                f"Impact Score: {impact_score}"
            )

        # Remediation

        remediation = vulnerability.get(
            "remediation"
        )

        if remediation:

            report.append("")
            report.append(
                "Remediation:"
            )

            report.append(
                str(remediation)
            )

        # Assessment Note

        assessment_note = vulnerability.get(
            "assessment_note"
        )

        if assessment_note:

            report.append("")
            report.append(
                "Assessment Note:"
            )

            report.append(
                str(assessment_note)
            )

    else:

        report.append(
            "No associated vulnerability identified."
        )

        report.append(
            "No CVE or CVSS information available."
        )

    # =========================================================
    # MITRE ATT&CK
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "MITRE ATT&CK"
    )

    report.append("-" * 70)

    if mitre_results:

        if isinstance(
            mitre_results,
            dict
        ):

            for key, value in mitre_results.items():

                report.append(
                    f"{key.replace('_', ' ').title()}: {value}"
                )

        elif isinstance(
            mitre_results,
            list
        ):

            for result in mitre_results:

                if isinstance(
                    result,
                    dict
                ):

                    for key, value in result.items():

                        report.append(
                            f"{key.replace('_', ' ').title()}: {value}"
                        )

                    report.append("")

                else:

                    report.append(
                        str(result)
                    )

        else:

            report.append(
                str(mitre_results)
            )

    else:

        report.append(
            "No MITRE ATT&CK techniques identified."
        )

    # =========================================================
    # ELASTICSEARCH IOC CORRELATION
    # =========================================================

    report.append("")
    report.append("-" * 70)

    report.append(
        "ELASTICSEARCH IOC CORRELATION"
    )

    report.append("-" * 70)

    if elastic_results:

        total_events = 0

        # The analyzer returns a list of IOC result dictionaries

        if isinstance(
            elastic_results,
            list
        ):

            for ioc_result in elastic_results:

                if not isinstance(
                    ioc_result,
                    dict
                ):

                    report.append(
                        str(ioc_result)
                    )

                    continue

                ioc = ioc_result.get(
                    "ioc",
                    "N/A"
                )

                category = ioc_result.get(
                    "category",
                    "Unknown"
                )

                matches = ioc_result.get(
                    "matches",
                    []
                )

                match_count = ioc_result.get(
                    "total_matches",
                    len(matches)
                )

                total_events += match_count

                report.append("")
                report.append(
                    f"IoC: {ioc}"
                )

                report.append(
                    f"Category: {category}"
                )

                report.append(
                    f"Total Matching Events: {match_count}"
                )

                if matches:

                    for event in matches:

                        if not isinstance(
                            event,
                            dict
                        ):

                            report.append(
                                str(event)
                            )

                            continue

                        report.append("")
                        report.append(
                            "Matching Event:"
                        )

                        report.append(
                            f"Timestamp: "
                            f"{event.get('timestamp', 'N/A')}"
                        )

                        report.append(
                            f"Host: "
                            f"{event.get('host', 'N/A')}"
                        )

                        report.append(
                            f"Event ID: "
                            f"{event.get('event_id', 'N/A')}"
                        )

                        report.append(
                            f"Provider: "
                            f"{event.get('provider', 'N/A')}"
                        )

                        report.append(
                            f"Message: "
                            f"{event.get('message', 'N/A')}"
                        )

                else:

                    report.append(
                        "No matching event details returned."
                    )

            report.append("")
            report.append(
                f"TOTAL MATCHING EVENTS: {total_events}"
            )

        # Support dictionary-based results as well

        elif isinstance(
            elastic_results,
            dict
        ):

            for ioc, results in elastic_results.items():

                report.append("")
                report.append(
                    f"IoC: {ioc}"
                )

                if isinstance(
                    results,
                    dict
                ):

                    matches = results.get(
                        "matches",
                        []
                    )

                    match_count = results.get(
                        "total_matches",
                        len(matches)
                    )

                    report.append(
                        f"Total Matching Events: {match_count}"
                    )

                    for event in matches:

                        if not isinstance(
                            event,
                            dict
                        ):
                            continue

                        report.append("")
                        report.append(
                            f"Timestamp: "
                            f"{event.get('timestamp', 'N/A')}"
                        )

                        report.append(
                            f"Host: "
                            f"{event.get('host', 'N/A')}"
                        )

                        report.append(
                            f"Event ID: "
                            f"{event.get('event_id', 'N/A')}"
                        )

                        report.append(
                            f"Provider: "
                            f"{event.get('provider', 'N/A')}"
                        )

                        report.append(
                            f"Message: "
                            f"{event.get('message', 'N/A')}"
                        )

                else:

                    report.append(
                        str(results)
                    )

        else:

            report.append(
                str(elastic_results)
            )

    else:

        report.append(
            "No matching Elasticsearch events found."
        )

    # =========================================================
    # FINAL REPORT
    # =========================================================

    report.append("")
    report.append("=" * 70)

    report.append(
        "END OF CYBERSHIELD ANALYSIS REPORT"
    )

    report.append("=" * 70)

    return "\n".join(report)
