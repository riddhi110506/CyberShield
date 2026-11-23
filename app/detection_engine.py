
import ipaddress
import re


class DetectionEngine:

    def __init__(self, es=None):
        self.es = es

    def get_severity(self, score):
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        return "LOW"

    def create_alert(
        self, event, rule, score, reason, process="", details=None
    ):
        return {
            "timestamp": event.get("@timestamp"),
            "host": event.get("host", {}).get("name", "Unknown"),
            "event_id": str(event.get("event", {}).get("code", "")),
            "rule": rule,
            "severity": self.get_severity(score),
            "risk_score": score,
            "reason": reason,
            "process": process,
            "details": details or {}
        }

    def analyze_event(self, event):

        alerts = []

        event_id = str(event.get("event", {}).get("code", ""))
        data = event.get("winlog", {}).get("event_data", {})

        # EVENT ID 1: PROCESS CREATION
        if event_id == "1":

            image = data.get("Image", "")
            command = data.get("CommandLine", "")
            process = image.lower().split("\\")[-1]
            command_lower = command.lower()

            suspicious_patterns = [
                "-encodedcommand",
                "-enc ",
                "-executionpolicy bypass",
                "-windowstyle hidden",
                "downloadstring",
                "invoke-webrequest",
                "frombase64string",
                "start-bitstransfer",
                "http://",
                "https://",
                "javascript:",
                "scrobj.dll"
            ]

            matches = [
                pattern for pattern in suspicious_patterns
                if pattern in command_lower
            ]

            if matches:
                alerts.append(
                    self.create_alert(
                        event,
                        "Suspicious Process Execution",
                        75,
                        "Process command line contains suspicious patterns: "
                        + ", ".join(matches),
                        image,
                        {"command_line": command}
                    )
                )

        # EVENT ID 3: NETWORK CONNECTION
        elif event_id == "3":

            image = data.get("Image", "")
            destination_ip = data.get("DestinationIp", "")
            destination_port = data.get("DestinationPort", "")

            process = image.lower().split("\\")[-1]

            try:
                ip = ipaddress.ip_address(destination_ip)
                is_public = ip.is_global
            except ValueError:
                is_public = False

            if process in ["powershell.exe", "pwsh.exe"] and is_public:
                alerts.append(
                    self.create_alert(
                        event,
                        "PowerShell Network Connection",
                        45,
                        "PowerShell initiated an outbound connection "
                        "to a public IP. Investigate its process context.",
                        image,
                        {
                            "destination_ip": destination_ip,
                            "destination_port": destination_port,
                            "protocol": data.get("Protocol")
                        }
                    )
                )

            suspicious_ports = ["4444", "1337", "31337", "6667"]

            if destination_port in suspicious_ports:
                alerts.append(
                    self.create_alert(
                        event,
                        "Suspicious Network Port",
                        60,
                        "Connection detected using a port commonly "
                        "associated with suspicious activity.",
                        image,
                        {
                            "destination_ip": destination_ip,
                            "destination_port": destination_port
                        }
                    )
                )

        # EVENT ID 8: REMOTE THREAD CREATION
        elif event_id == "8":

            source_image = data.get("SourceImage", "")
            target_image = data.get("TargetImage", "")
            target_process = target_image.lower().split("\\")[-1]

            score = 45
            reason = (
                "Remote thread creation detected. "
                "Review source and target process relationships."
            )

            if target_process in ["lsass.exe", "winlogon.exe"]:
                score = 75
                reason = (
                    "Remote thread creation targeting a sensitive "
                    "Windows process."
                )

            alerts.append(
                self.create_alert(
                    event,
                    "Remote Thread Creation",
                    score,
                    reason,
                    source_image,
                    {
                        "source_process": source_image,
                        "target_process": target_image,
                        "start_module": data.get("StartModule"),
                        "start_function": data.get("StartFunction")
                    }
                )
            )

        # EVENT ID 11: FILE CREATION
        elif event_id == "11":

            image = data.get("Image", "")
            filename = data.get("TargetFilename", "")

            file_lower = filename.lower()

            suspicious_extensions = (
                ".exe", ".dll", ".scr", ".bat",
                ".cmd", ".ps1", ".vbs", ".js", ".hta"
            )

            suspicious_locations = [
                "\\appdata\\",
                "\\temp\\",
                "\\startup\\",
                "\\users\\public\\"
            ]

            has_suspicious_extension = file_lower.endswith(
                suspicious_extensions
            )

            has_suspicious_location = any(
                location in file_lower
                for location in suspicious_locations
            )

            if has_suspicious_extension and has_suspicious_location:
                alerts.append(
                    self.create_alert(
                        event,
                        "Suspicious File Creation",
                        60,
                        "Executable or script file created in a "
                        "user-writable or startup location.",
                        image,
                        {"target_filename": filename}
                    )
                )

        # EVENT ID 22: DNS QUERY
        elif event_id == "22":

            image = data.get("Image", "")
            domain = data.get("QueryName", "").lower().rstrip(".")

            labels = domain.split(".")

            suspicious_reasons = []

            if domain.startswith("xn--") or ".xn--" in domain:
                suspicious_reasons.append("Punycode domain")

            if len(domain) > 60:
                suspicious_reasons.append("Unusually long domain")

            if len(labels) > 5:
                suspicious_reasons.append("Excessive subdomains")

            if any(len(label) > 30 for label in labels):
                suspicious_reasons.append("Unusually long domain label")

            if suspicious_reasons:
                alerts.append(
                    self.create_alert(
                        event,
                        "Suspicious DNS Query",
                        45,
                        ", ".join(suspicious_reasons),
                        image,
                        {"query_name": domain}
                    )
                )

        return alerts

    def scan_elasticsearch(
        self,
        index_pattern=".ds-logs-winlog.winlog-default-*"
    ):

        if self.es is None:
            raise ValueError("Elasticsearch client is required.")

        response = self.es.search(
            index=index_pattern,
            query={
                "terms": {
                    "event.code": ["1", "3", "8", "11", "22"]
                }
            },
            size=3000,
            sort=[
                {"@timestamp": {"order": "desc"}}
            ]
        )

        hits = response["hits"]["hits"]

        all_alerts = []

        for hit in hits:
            event = hit["_source"]
            alerts = self.analyze_event(event)
            all_alerts.extend(alerts)

        return {
            "total_events_scanned": len(hits),
            "total_alerts": len(all_alerts),
            "alerts": all_alerts
        }
