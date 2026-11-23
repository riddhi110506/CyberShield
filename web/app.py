import re
import uuid
import tempfile
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    send_from_directory,
    abort
)
from werkzeug.utils import secure_filename

from app.analyzer import CyberShieldAnalyzer


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
UPLOADS_DIR = BASE_DIR / "uploads"

REPORTS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_SIZE = 20 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

analyzer = CyberShieldAnalyzer()


def save_report(report, input_type):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = (
        f"{input_type.lower()}_report_{timestamp}_"
        f"{uuid.uuid4().hex[:8]}.txt"
    )

    report_path = REPORTS_DIR / filename
    report_path.write_text(report, encoding="utf-8")

    return filename


def extract_dashboard_metrics(report):
    risk_match = re.search(
        r"Risk Score:\s*(\d+(?:\.\d+)?)(?:/100)?",
        report,
        re.IGNORECASE
    )

    severity_match = re.search(
        r"Severity:\s*([A-Za-z]+)",
        report,
        re.IGNORECASE
    )

    malicious = len(re.findall(
        r"status:\s*malicious",
        report,
        re.IGNORECASE
    ))

    suspicious = len(re.findall(
        r"status:\s*suspicious",
        report,
        re.IGNORECASE
    ))

    event_matches = re.findall(
        r"Total Matching Events:\s*(\d+)",
        report,
        re.IGNORECASE
    )

    return {
        "risk_score": (
            risk_match.group(1) if risk_match else "N/A"
        ),
        "severity": (
            severity_match.group(1).capitalize()
            if severity_match else "Not available"
        ),
        "malicious": malicious,
        "suspicious": suspicious,
        "elastic_events": sum(
            int(value) for value in event_matches
        )
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    analysis_type = request.form.get("analysis_type", "").strip()

    report = None
    error = None
    metrics = None
    report_filename = None
    input_label = None

    temporary_path = None

    try:
        if analysis_type == "url":
            url = request.form.get("url", "").strip()

            if not url:
                raise ValueError("Please enter a URL.")

            input_label = url
            report = analyzer.analyze_url(url)

        elif analysis_type == "file":
            uploaded_file = request.files.get("file")

            if not uploaded_file or not uploaded_file.filename:
                raise ValueError("Please select a file.")

            safe_name = secure_filename(uploaded_file.filename)

            if not safe_name:
                raise ValueError("Invalid filename.")

            suffix = Path(safe_name).suffix

            with tempfile.NamedTemporaryFile(
                prefix="cybershield_",
                suffix=suffix,
                dir=UPLOADS_DIR,
                delete=False
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                uploaded_file.save(temporary_file)

            input_label = safe_name
            report = analyzer.analyze_file(str(temporary_path))

        else:
            raise ValueError("Select file analysis or URL analysis.")

        if report is None:
            raise ValueError(
                "Analysis could not be completed. Check the supplied input."
            )

        metrics = extract_dashboard_metrics(report)
        report_filename = save_report(report, analysis_type.upper())

    except ValueError as exc:
        error = str(exc)

    except OSError as exc:
        error = f"File operation failed: {exc}"

    except Exception:
        app.logger.exception("CyberShield analysis failed.")
        error = (
            "Analysis failed unexpectedly. Check the dashboard "
            "terminal for details."
        )

    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()

    return render_template(
        "index.html",
        report=report,
        error=error,
        metrics=metrics,
        report_filename=report_filename,
        input_label=input_label
    )


@app.route("/download/<filename>")
def download_report(filename):
    safe_filename = secure_filename(filename)

    if safe_filename != filename:
        abort(404)

    report_path = REPORTS_DIR / safe_filename

    if not report_path.is_file():
        abort(404)

    return send_from_directory(
        REPORTS_DIR,
        safe_filename,
        as_attachment=True
    )


@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        "index.html",
        error="File is too large. Maximum upload size is 20 MB."
    ), 413


if __name__ == "__main__":
    print("\nStarting CyberShield dashboard...")

    # Establish Elasticsearch connection once before web requests.
    # Password entry remains hidden in this terminal.
    try:
        analyzer.get_elasticsearch()
    except Exception as exc:
        print("Elasticsearch unavailable:", exc)

    print("Dashboard: http://127.0.0.1:5000")
    print("Press CTRL+C to stop.")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
