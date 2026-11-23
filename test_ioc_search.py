from app.elastic_client import create_client


def search_ioc(ioc):
    es = create_client()

    try:
        response = es.search(
            index=".ds-logs-winlog.winlog-default-*",
            query={
                "match_phrase": {
                    "message": ioc
                }
            },
            size=10,
            source=[
                "@timestamp",
                "host.name",
                "event.code",
                "event.provider",
                "message",
                "winlog.event_data"
            ]
        )

        hits = response["hits"]["hits"]

        print("\n========== IOC CORRELATION RESULTS ==========")
        print("Indicator:", ioc)
        print("Matching events:", response["hits"]["total"]["value"])

        if not hits:
            print("No matching events found.")

        for number, hit in enumerate(hits, start=1):
            event = hit["_source"]

            print(f"\n--- Match {number} ---")
            print("Timestamp:", event.get("@timestamp"))
            print("Host:", event.get("host", {}).get("name"))
            print("Event ID:", event.get("event", {}).get("code"))
            print("Provider:", event.get("event", {}).get("provider"))
            print("Message:", event.get("message", "")[:500])

    finally:
        es.close()


if __name__ == "__main__":
    test_hash = (
        "CE2368D41495CEED82032BC29F2D68BCB92F8EA93A0A2EB45BC2900E22EDC06D"
    )

    search_ioc(test_hash)
