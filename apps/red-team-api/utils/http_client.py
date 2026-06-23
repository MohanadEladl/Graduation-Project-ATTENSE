"""
utils/http_client.py — Shared HTTP session (legacy compatibility).

The new BaseModule has its own _get / _post helpers.
This module is kept for any standalone utility scripts.
"""
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def create_session(user_agent: str = "ATTENSE-RedTeam/2.0") -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    return s
