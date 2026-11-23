import os
from getpass import getpass
from elasticsearch import Elasticsearch
from elasticsearch import ConnectionError, AuthenticationException


def create_client(password=None, prompt=True):
    """
    Connect to the local Elasticsearch instance.

    Password priority:
    1. Explicit password argument.
    2. ELASTICSEARCH_PASSWORD environment variable.
    3. Hidden terminal prompt, when prompt=True.
    """

    username = os.getenv("ELASTICSEARCH_USERNAME", "elastic")

    if password is None:
        password = os.getenv("ELASTICSEARCH_PASSWORD")

    if not password and prompt:
        password = getpass("Enter Elasticsearch password: ")

    if not password:
        raise ValueError(
            "Elasticsearch password is not configured."
        )

    es = Elasticsearch(
        "https://localhost:9200",
        basic_auth=(username, password),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=10
    )

    try:
        if es.ping():
            print("Successfully connected to Elasticsearch!")
            return es

        es.close()
        raise ConnectionError(
            "Elasticsearch server did not respond."
        )

    except AuthenticationException:
        es.close()
        print("Elasticsearch authentication failed.")
        raise

    except Exception:
        es.close()
        raise
