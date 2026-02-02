import json
import time
import requests

from app.redis_client import redis_client
from app.config import config
from falcoria_common.redis.redis_keys import RedisKeyBuilder


def get_external_ip() -> str:
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except Exception:
        return "unknown"


def register_worker_ip():
    ip = get_external_ip()
    hostname = config.hostname
    key = RedisKeyBuilder.worker_key(hostname)

    data = {
        "ip": ip,
        "last_updated": int(time.time())
    }

    redis_client.hset(key, mapping=data)