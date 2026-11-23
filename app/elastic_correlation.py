def correlate_ioc(es, ioc, size=10):
    """
    Search Windows telemetry in Elasticsearch for an IOC.

    Returns matching events with their relevant fields.
    """

    response = es.search(
        index=".ds-logs-winlog.winlog-default-*",
        query={
            "match_phrase": {
                "message": ioc
            }
        },
        size=size,
        source=[
            "@timestamp",
            "host.name",
            "event.code",
            "event.provider",
            "message"
        ]
    )

    hits = response.get(
        "hits",
        {}
    ).get(
        "hits",
        []
    )

    total = response.get(
        "hits",
        {}
    ).get(
        "total",
        0
    )

    # Elasticsearch may return total as a dictionary

    if isinstance(total, dict):

        total = total.get(
            "value",
            0
        )

    matches = []

    for hit in hits:

        event = hit.get(
            "_source",
            {}
        )

        host_data = event.get(
            "host",
            {}
        )

        event_data = event.get(
            "event",
            {}
        )

        if not isinstance(host_data, dict):
            host_data = {}

        if not isinstance(event_data, dict):
            event_data = {}

        matches.append({

            "timestamp": event.get(
                "@timestamp",
                "N/A"
            ),

            "host": host_data.get(
                "name",
                "N/A"
            ),

            "event_id": event_data.get(
                "code",
                "N/A"
            ),

            "provider": event_data.get(
                "provider",
                "N/A"
            ),

            "message": event.get(
                "message",
                "N/A"
            )

        })

    return {

        "ioc": ioc,

        "total_matches": total,

        "matches": matches

    }
