# config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Config(BaseSettings):
    rabbitmq_host: str = "myserver"
    rabbitmq_port: int = 5672
    rabbitmq_user: str
    rabbitmq_password: str
    rabbitmq_vhost: str = "my_vhost"

    celery_app_name: str = "nmap_celery_consumer"
    exchange_name: str = "nmap_exchange"
    exchange_type: str = "topic"
    queue: str = "nmap_queue"
    routing_key: str = "nmap.#"
    nmap_scan_queue_name: str = "nmap_scan_queue"
    nmap_cancel_queue_name: str = "nmap_cancel_queue"
    nmap_scan_routing_key: str = "nmap.scan"
    nmap_cancel_routing_key: str = "nmap.cancel"

    redis_pass: str
    redis_host: str = "myserver"
    redis_port: int = 6379
    redis_db: int = 3

    nmap_open_ports_opts: str = "-p- --open"
    nmap_service_opts: str = "-sV -Pn -T4"

    logger_name: str = "worker_logger"
    logger_level: str = "DEBUG"

    backend_base_url: str = "http://localhost:8000"
    worker_backend_token: str

    model_config = SettingsConfigDict(env_file=".env")

    @property
    def ampq_connection_str(self):
        return f"pyamqp://{self.rabbitmq_user}:{self.rabbitmq_password}@{self.rabbitmq_host}:{self.rabbitmq_port}/{self.rabbitmq_vhost}"

    @property
    def redis_connection_str(self):
        return f"redis://:{self.redis_pass}@{self.redis_host}:{self.redis_port}/{self.redis_db}"


config = Config()