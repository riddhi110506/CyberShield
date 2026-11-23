from app.elastic_client import create_client
from app.elastic_correlation import correlate_ioc


if __name__ == "__main__":
    es = create_client()

    try:
        test_hash = (
            "CE2368D41495CEED82032BC29F2D68BCB92F8EA93A0A2"
            "EB45BC2900E22EDC06D"
        )

        result = correlate_ioc(es, test_hash)

        print("\n========== CYBERSHIELD IOC CORRELATION ==========")
        print("IOC:", result["ioc"])
        print("Total matching events:", result["total_matches"])

        for number, event in enumerate(result["matches"], start=1):
            print(f"\n--- Event {number} ---")
            print("Timestamp:", event["timestamp"])
            print("Host:", event["host"])
            print("Event ID:", event["event_id"])
            print("Provider:", event["provider"])
            print("Message:", event["message"][:300])

    finally:
        es.close()
