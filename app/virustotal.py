

import requests
import base64


class VirusTotal:

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key):
        self.api_key = api_key

    def _not_configured(self, indicator, indicator_type):
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": "not_configured",
            "source": "VirusTotal"
        }

    def _check_indicator(self, indicator, indicator_type, endpoint):

        if not self.api_key:
            return self._not_configured(indicator, indicator_type)

        headers = {
            "x-apikey": self.api_key
        }

        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=headers,
                timeout=15
            )

            if response.status_code == 200:

                data = response.json()

                attributes = (
                    data.get("data", {})
                    .get("attributes", {})
                )

                stats = attributes.get(
                    "last_analysis_stats", {}
                )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0:
                    status = "malicious"

                elif suspicious > 0:
                    status = "suspicious"

                else:
                    status = "clean"

                return {
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "status": status,
                    "source": "VirusTotal",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }

            elif response.status_code == 404:
                status = "not_found"

            elif response.status_code in [401, 403]:
                status = "invalid_api_key"

            elif response.status_code == 429:
                status = "rate_limited"

            else:
                status = "error"

            result = {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "status": status,
                "source": "VirusTotal"
            }

            if status == "error":
                result["http_status"] = response.status_code

            return result

        except requests.RequestException:
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "status": "error",
                "source": "VirusTotal"
            }

        except ValueError:
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "status": "error",
                "source": "VirusTotal"
            }

    # File hash reputation

    def check_hash(self, file_hash):

        return self._check_indicator(
            file_hash,
            "hash",
            f"files/{file_hash}"
        )

    # URL reputation

    def check_url(self, url):

        url_id = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("utf-8").rstrip("=")

        return self._check_indicator(
            url,
            "url",
            f"urls/{url_id}"
        )

    # Domain reputation

    def check_domain(self, domain):

        return self._check_indicator(
            domain,
            "domain",
            f"domains/{domain}"
        )

    # IP address reputation

    def check_ip(self, ip_address):

        return self._check_indicator(
            ip_address,
            "ip",
            f"ip_addresses/{ip_address}"
        )
