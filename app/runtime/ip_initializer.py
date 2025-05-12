import socket
import requests
from app.redis_client import redis_client


REDIS_KEY = "worker_ips"


def get_external_ip() -> str:
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
        return ip
    except Exception:
        return "unknown"


def get_hostname() -> str:
    return socket.gethostname()


def register_worker_ip():
    ip = get_external_ip()
    hostname = get_hostname()
    redis_client.hset(REDIS_KEY, hostname, ip)
