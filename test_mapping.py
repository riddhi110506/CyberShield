from app.elastic_client import create_client
import json


def inspect_mapping():
    es = create_client()

    try:
        mappings = es.indices.get_mapping(
            index=".ds-logs-winlog.winlog-default-*"
        )

        print("\n========== DETAILED FIELD MAPPINGS ==========")

        target_fields = [
            "message",
            "winlog",
            "process",
            "source",
            "destination",
            "url",
            "dns",
            "file",
            "user",
            "network",
            "related",
            "event",
            "host"
        ]

        for index, details in mappings.items():
            properties = details.get("mappings", {}).get("properties", {})

            print(f"\n\nINDEX: {index}")
            print("\nAvailable top-level fields:")
            print(", ".join(sorted(properties.keys())))

            for field in target_fields:
                if field in properties:
                    print(f"\n--- {field} ---")
                    print(json.dumps(
                        properties[field],
                        indent=2
                    ))

    finally:
        es.close()


if __name__ == "__main__":
    inspect_mapping()
