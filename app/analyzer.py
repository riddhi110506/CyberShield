from app.file_analyzer import analyze_file
from app.url_analyzer import analyze_url
from app.ioc_extractor import extract_iocs
from app.threat_intel import ThreatIntelligence

from app.risk_engine import (
    calculate_risk_score,
    calculate_threat_intel_score
)

from app.vulnerability import (
    create_vulnerability_result,
    analyze_vulnerabilities
)

from app.mitre_attack import map_behaviors
from app.report import generate_report

from app.feature_detector import (
    analyze_url_features,
    analyze_file_features
)

from app.static_analyzer import analyze_static_file

# Elasticsearch integration
from app.elastic_client import create_client
from app.elastic_correlation import correlate_ioc


class CyberShieldAnalyzer:

    def __init__(self):

        self.threat_intel = ThreatIntelligence()

        # Elasticsearch connection
        self.es = None
        self.elastic_error = None

    # --------------------------------------------------
    # ELASTICSEARCH CONNECTION
    # --------------------------------------------------

    def get_elasticsearch(self):

        if self.es is not None:
            return self.es

        if self.elastic_error is not None:
            return None

        try:

            self.es = create_client()
            return self.es

        except Exception as error:

            self.elastic_error = str(error)

            print(
                "Elasticsearch unavailable:",
                error
            )

            return None

    # --------------------------------------------------
    # IOC CORRELATION WITH ELASTICSEARCH
    # --------------------------------------------------

    def correlate_iocs(self, iocs):

        es = self.get_elasticsearch()

        if es is None:
            return []

        results = []
        checked_iocs = set()

        for category, values in iocs.items():

            for ioc in values or []:

                if not isinstance(ioc, str):
                    continue

                ioc = ioc.strip()

                if not ioc:
                    continue

                if ioc in checked_iocs:
                    continue

                checked_iocs.add(ioc)

                try:

                    result = correlate_ioc(
                        es,
                        ioc
                    )

                    if not isinstance(result, dict):
                        continue

                    result["category"] = category

                    results.append(result)

                except Exception as error:

                    print(
                        f"IOC correlation failed for {ioc}: "
                        f"{error}"
                    )

        return results

    # --------------------------------------------------
    # FILE ANALYSIS
    # --------------------------------------------------

    def analyze_file(self, file_path):

        # 1. Basic file analysis

        analysis = analyze_file(file_path)

        if analysis is None:
            return None

        # 2. Static analysis

        static_result = analyze_static_file(
            file_path
        )

        # 3. Extract IoCs

        analysis_text = str(analysis)

        iocs = extract_iocs(
            analysis_text
        )

        # Add MD5 hash

        if analysis.get("md5"):

            if analysis["md5"] not in iocs["hashes"]:

                iocs["hashes"].append(
                    analysis["md5"]
                )

        # Add SHA-256 hash

        if analysis.get("sha256"):

            if analysis["sha256"] not in iocs["hashes"]:

                iocs["hashes"].append(
                    analysis["sha256"]
                )

        # Add URLs from static analysis

        for url in static_result.get("urls", []):

            if url not in iocs["urls"]:

                iocs["urls"].append(url)

        # Add IP addresses

        for ip in static_result.get(
            "ip_addresses",
            []
        ):

            if ip not in iocs["ip_addresses"]:

                iocs["ip_addresses"].append(ip)

        # 4. Feature analysis

        feature_result = analyze_file_features(
            analysis
        )

        # Additional score from static findings

        static_score = 0

        if static_result.get("urls"):
            static_score += 10

        if static_result.get("ip_addresses"):
            static_score += 10

        suspicious_terms = static_result.get(
            "suspicious_terms",
            []
        )

        if suspicious_terms:

            static_score += min(
                len(suspicious_terms) * 15,
                40
            )

        feature_result["score"] = min(
            feature_result.get("score", 0)
            + static_score,
            100
        )

        # Add static findings to evidence

        if static_result.get("urls"):

            feature_result["findings"].append({

                "finding": (
                    "URL(s) found in file: "
                    + ", ".join(
                        static_result["urls"]
                    )
                ),

                "score": 10

            })

        if static_result.get("ip_addresses"):

            feature_result["findings"].append({

                "finding": (
                    "IP address(es) found in file: "
                    + ", ".join(
                        static_result["ip_addresses"]
                    )
                ),

                "score": 10

            })

        if suspicious_terms:

            feature_result["findings"].append({

                "finding": (
                    "Suspicious command/tool reference(s) found: "
                    + ", ".join(
                        suspicious_terms
                    )
                ),

                "score": min(
                    len(suspicious_terms) * 15,
                    40
                )

            })

        # 5. Threat intelligence

        threat_results = []

        for hash_value in iocs.get(
            "hashes",
            []
        ):

            result = self.threat_intel.check_hash(
                hash_value
            )

            threat_results.append(result)

        threat_intel_score = (
            calculate_threat_intel_score(
                threat_results
            )
        )

        # 6. Vulnerability assessment

        try:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                file_content = file.read()

            vulnerability = (
                analyze_vulnerabilities(
                    file_content
                )
            )

        except Exception as error:

            vulnerability = (
                create_vulnerability_result()
            )

            vulnerability["assessment_note"] = (
                "Vulnerability analysis could not "
                f"be completed: {error}"
            )

        # Convert CVSS score into a 0-100 score

        vulnerability_score = None

        cvss_score = vulnerability.get(
            "cvss_score"
        )

        if cvss_score is not None:

            try:

                vulnerability_score = float(
                    cvss_score
                ) * 10

                vulnerability_score = min(
                    max(
                        vulnerability_score,
                        0
                    ),
                    100
                )

            except (
                ValueError,
                TypeError
            ):

                vulnerability_score = None

        # 7. Risk assessment

        risk = calculate_risk_score(

            threat_intel_score=(
                threat_intel_score
            ),

            suspicious_features_score=(
                feature_result["score"]
            ),

            ioc_score=0,

            analysis_score=0,

            vulnerability_score=(
                vulnerability_score
            )

        )

        # 8. MITRE ATT&CK mapping

        mitre_behaviors = []

        for term in suspicious_terms:

            if term == "powershell":

                mitre_behaviors.append(
                    "powershell"
                )

            elif term == "certutil":

                mitre_behaviors.append(
                    "certutil"
                )

        mitre_results = map_behaviors(
            mitre_behaviors
        )

        # 9. Elasticsearch IOC correlation

        print(
            "\nStarting Elasticsearch IOC correlation..."
        )

        elastic_results = self.correlate_iocs(
            iocs
        )

        # 10. Generate report

        report = generate_report(

            "FILE",

            file_path,

            analysis,

            iocs,

            threat_results,

            risk,

            vulnerability,

            mitre_results,

            feature_result,

            static_result,

            elastic_results=elastic_results

        )

        return report

    # --------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------

    def analyze_url(self, url):

        # 1. URL analysis

        analysis = analyze_url(url)

        if analysis is None:
            return None

        # 2. Extract IoCs

        analysis_text = str(analysis)

        iocs = extract_iocs(
            analysis_text
        )

        # Add domain when the host is not an IP

        domain = analysis.get(
            "domain"
        )

        if (
            not analysis.get(
                "is_ip_address",
                False
            )
            and domain
        ):

            if domain not in iocs["domains"]:

                iocs["domains"].append(
                    domain
                )

        # Add URL

        if analysis["url"] not in iocs["urls"]:

            iocs["urls"].append(
                analysis["url"]
            )

        # Add IP address

        if analysis.get(
            "is_ip_address",
            False
        ):

            if domain not in iocs["ip_addresses"]:

                iocs["ip_addresses"].append(
                    domain
                )

        # 3. Feature analysis

        feature_result = analyze_url_features(
            analysis
        )

        # 4. Threat intelligence

        threat_results = []

        # Check URL

        for url_value in iocs.get(
            "urls",
            []
        ):

            result = self.threat_intel.check_url(
                url_value
            )

            threat_results.append(result)

        # Check domain

        for domain_value in iocs.get(
            "domains",
            []
        ):

            result = self.threat_intel.check_domain(
                domain_value
            )

            threat_results.append(result)

        # Check IP

        if analysis.get(
            "is_ip_address",
            False
        ):

            result = self.threat_intel.check_ip(
                domain
            )

            threat_results.append(result)

        threat_intel_score = (
            calculate_threat_intel_score(
                threat_results
            )
        )

        # 5. Vulnerability assessment

        vulnerability = (
            create_vulnerability_result()
        )

        vulnerability_score = None

        # 6. Risk assessment

        risk = calculate_risk_score(

            threat_intel_score=(
                threat_intel_score
            ),

            suspicious_features_score=(
                feature_result["score"]
            ),

            ioc_score=0,

            analysis_score=0,

            vulnerability_score=(
                vulnerability_score
            )

        )

        # 7. MITRE ATT&CK

        mitre_results = map_behaviors(
            []
        )

        # 8. Elasticsearch IOC correlation

        print(
            "\nStarting Elasticsearch IOC correlation..."
        )

        elastic_results = self.correlate_iocs(
            iocs
        )

        # 9. Generate report

        report = generate_report(

            "URL",

            url,

            analysis,

            iocs,

            threat_results,

            risk,

            vulnerability,

            mitre_results,

            feature_result,

            None,

            elastic_results=elastic_results

        )

        return report

    # --------------------------------------------------
    # CLOSE ELASTICSEARCH CONNECTION
    # --------------------------------------------------

    def close(self):

        if self.es is not None:

            self.es.close()

            self.es = None

            print(
                "Elasticsearch connection closed."
            )
