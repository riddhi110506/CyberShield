from app.elastic_client import create_client


def retrieve_sysmon_events():
    es = create_client()

    try:
        response = es.search(
            index=".ds-logs-winlog.winlog-default-*",
            size=5,
            sort=[{"@timestamp": {"order": "desc"}}],
            source=[
                "@timestamp",
                "host.name",
                "event.code",
                "winlog.channel",
                "event.provider",
                "message"
            ]
        )

        hits = response["hits"]["hits"]

        print("\n========== WINDOWS SYSMON EVENTS ==========")
        print(f"Total matching events: {response['hits']['total']['value']}")

        for number, hit in enumerate(hits, start=1):
            event = hit["_source"]

            print(f"\n--- Event {number} ---")
            print("Timestamp:", event.get("@timestamp"))
            print("Host:", event.get("host", {}).get("name"))
            print("Event ID:", event.get("event", {}).get("code"))
            print("Provider:", event.get("event", {}).get("provider"))
            print("Channel:", event.get("winlog", {}).get("channel"))
            print("Message:", event.get("message", "Not available")[:300])

    finally:
        es.close()


if __name__ == "__main__":
    retrieve_sysmon_events()
