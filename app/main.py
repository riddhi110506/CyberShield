from app.analyzer import CyberShieldAnalyzer
from datetime import datetime
from pathlib import Path


def save_report(report, input_type):
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"{input_type.lower()}_report_{timestamp}.txt"
    report_path = reports_dir / filename

    report_path.write_text(report, encoding="utf-8")

    return report_path


def main():
    analyzer = CyberShieldAnalyzer()

    while True:
        print("\n" + "=" * 50)
        print("        CYBERSHIELD")
        print("Threat Analysis & Risk Assessment Platform")
        print("=" * 50)

        print("\n1. Analyze File")
        print("2. Analyze URL")
        print("3. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            file_path = input("\nEnter file path: ").strip()

            try:
                report = analyzer.analyze_file(file_path)

                if report is None:
                    print("\nFile not found or could not be analyzed.")
                else:
                    print("\n")
                    print(report)

                    saved_path = save_report(report, "FILE")
                    print(f"\nReport saved successfully: {saved_path}")

            except (OSError, ValueError) as error:
                print(f"\nFile analysis error: {error}")

        elif choice == "2":
            url = input("\nEnter URL: ").strip()

            try:
                report = analyzer.analyze_url(url)

                if report is None:
                    print("\nInvalid URL.")
                else:
                    print("\n")
                    print(report)

                    saved_path = save_report(report, "URL")
                    print(f"\nReport saved successfully: {saved_path}")

            except (OSError, ValueError) as error:
                print(f"\nURL analysis error: {error}")

        elif choice == "3":
            print("\nExiting CyberShield...")
            break

        else:
            print("\nInvalid option.")


if __name__ == "__main__":
    main()
