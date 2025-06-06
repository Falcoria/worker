import socket
import requests
import json
import time

from app.redis_client import redis_client
from app.config import config


def get_external_ip() -> str:
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except Exception:
        return "unknown"


def get_hostname() -> str:
    return socket.gethostname()


def register_worker_ip():
    ip = get_external_ip()
    hostname = get_hostname()
    key = f"worker_ip:{hostname}"

    data = {
        "ip": ip,
        "last_updated": int(time.time())
    }

    redis_client.setex(key, config.ip_entry_ttl, json.dumps(data))
