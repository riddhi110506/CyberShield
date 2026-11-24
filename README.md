# 🛡️ CyberShield
### Threat Analysis & Risk Assessment Platform

CyberShield is a cybersecurity analysis platform designed to analyze suspicious URLs and files, identify potential security threats, calculate risk scores, investigate threat intelligence, and correlate Indicators of Compromise (IOCs) with security logs.

The platform combines static analysis, threat intelligence, vulnerability assessment, MITRE ATT&CK mapping, and Elasticsearch log correlation to provide security analysts with a centralized analysis dashboard.

## 🎯 Project Objective

The main objective of CyberShield is to help security analysts investigate suspicious URLs and files by identifying potential threats, analyzing security indicators, assessing risks, and presenting the results through a web-based dashboard.

## ✨ Features

- **URL Analysis:** Analyze URLs to identify suspicious characteristics, domains, IP addresses, ports, and potentially malicious patterns.
- **File Analysis:** Perform file metadata and static analysis, including file hashes, suspicious strings, URLs, IP addresses, and other indicators.
- **Risk Assessment:** Calculate risk scores based on detected suspicious indicators and threat intelligence results.
- **Threat Intelligence:** Integrate VirusTotal to investigate URLs, file hashes, domains, and IP addresses.
- **Vulnerability Assessment:** Identify applicable vulnerabilities and provide CVE and CVSS-related information when available.
- **MITRE ATT&CK Mapping:** Map detected suspicious behaviors to relevant MITRE ATT&CK techniques.
- **IOC Extraction:** Extract Indicators of Compromise such as URLs, IP addresses, domains, and file hashes.
- **Elastic SIEM Correlation:** Search Elasticsearch security telemetry for matching IOCs and investigate related events.
- **Security Reports:** Generate analysis reports containing findings, risk assessment, threat intelligence, and investigation results.
- **Web Dashboard:** Provide a centralized interface for submitting URLs and files and viewing analysis results.

## 🏗️ Architecture

CyberShield follows a modular architecture:

1. **Input Layer:** Accepts URLs or files from the user.
2. **Analysis Layer:** Performs URL analysis, file metadata analysis, and static inspection.
3. **Detection Layer:** Identifies suspicious indicators and potential malicious characteristics.
4. **Threat Intelligence Layer:** Retrieves reputation information from VirusTotal.
5. **Risk Assessment Layer:** Calculates a risk score based on analysis findings.
6. **Vulnerability Assessment Layer:** Identifies vulnerability information and CVSS scores when applicable.
7. **MITRE ATT&CK Layer:** Maps detected behaviors to ATT&CK techniques.
8. **SIEM Correlation Layer:** Searches Elasticsearch logs for IOC matches.
9. **Reporting Layer:** Generates structured analysis reports.
10. **Presentation Layer:** Displays findings through the Flask web dashboard.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Flask | Web application and dashboard |
| HTML | Dashboard interface |
| CSS | Dashboard styling |
| VirusTotal API | Threat intelligence |
| Elasticsearch | Security log search and IOC correlation |
| MITRE ATT&CK | Threat behavior mapping |
| CVSS | Vulnerability severity assessment |
| Git & GitHub | Version control and project hosting |


## 📂 Project Structure

```text
CyberShield/
│
├── app/
│   ├── analyzer.py
│   ├── detection_engine.py
│   ├── elastic_client.py
│   ├── elastic_correlation.py
│   ├── feature_detector.py
│   ├── file_analyzer.py
│   ├── ioc_extractor.py
│   ├── main.py
│   ├── mitre_attack.py
│   ├── report.py
│   ├── risk_engine.py
│   ├── static_analyzer.py
│   ├── threat_intel.py
│   ├── url_analyzer.py
│   ├── virustotal.py
│   ├── vulnerability.py
│   └── vulnerability_scanner.py
│
├── config/
│   └── settings.py
│
├── web/
│   ├── app.py
│   ├── static/
│   │   └── style.css
│   └── templates/
│       └── index.html
│
├── samples/
├── reports/
├── requirements.txt
├── Procfile
├── render.yaml
├── .gitignore
└── README.md
```

## ⚙️ Installation

### Prerequisites

- Python 3
- Git
- VirusTotal API key (optional, for threat intelligence)
- Elasticsearch instance (required for SIEM correlation)

### 1. Clone the Repository

```bash
git clone https://github.com/riddhi110506/CyberShield.git
cd CyberShield
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

Linux/macOS:

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables

Create a `.env` file in the project root directory.

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Configure Elasticsearch credentials and connection settings according to your local environment.

**Never upload API keys, passwords, or secret credentials to GitHub.**

## 🚀 Running CyberShield

### Web Dashboard

Run the Flask dashboard:

```bash
python -m web.app
```

Open your browser:

```text
http://127.0.0.1:5000
```

### Command-Line Interface

Run:

```bash
python -m app.main
```

The CLI provides options to analyze files and URLs.

## 🔍 Analysis Workflow

```text
User Input (URL/File)
        │
        ▼
Input Analysis
        │
        ▼
Static Analysis & IOC Extraction
        │
        ▼
Threat Detection
        │
        ▼
VirusTotal Threat Intelligence
        │
        ▼
Risk Assessment
        │
        ▼
Vulnerability Assessment
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Elasticsearch IOC Correlation
        │
        ▼
Analysis Report & Dashboard
```

## 📊 Risk Assessment

CyberShield evaluates suspicious characteristics and threat intelligence information to determine an overall risk score.

The assessment categorizes findings into risk levels such as:

- **Low Risk**
- **Moderate Risk**
- **High Risk**
- **Critical Risk**

The risk score is intended to help analysts prioritize investigations.

## 🛡️ Security Integrations

### VirusTotal

VirusTotal is used to investigate suspicious indicators and obtain threat reputation information.

### Elasticsearch

Elasticsearch is used to search security telemetry and correlate extracted IOCs with events collected from the security monitoring environment.

### MITRE ATT&CK

Detected suspicious behaviors are mapped to relevant MITRE ATT&CK tactics and techniques to support threat investigation.

## 🎓 Project Information

**Project Name:** CyberShield

**Project Type:** Cybersecurity / Threat Analysis Platform

**Domain:** Cybersecurity and Security Operations

**Developer:** Riddhi Thakur

## ⚠️ Disclaimer

CyberShield is an educational and security research project. Its analysis results are intended to support investigation and should not be considered a definitive determination of whether a file or URL is malicious.

Always use appropriate security precautions when analyzing suspicious files, URLs, and security indicators.

## 🔮 Future Enhancements

- Advanced threat detection
- Additional threat intelligence integrations
- Enhanced SIEM correlation
- Improved dashboard visualization
- Automated incident investigation
- Cloud deployment
- Additional file analysis capabilities

---

**CyberShield — Analyze. Detect. Investigate.**

