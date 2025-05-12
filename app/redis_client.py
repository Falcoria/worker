import redis

from app.config import config

redis_client = redis.StrictRedis(
    host=config.redis_host,
    port=config.redis_port,
    db=config.redis_db,
    password=config.redis_pass
)