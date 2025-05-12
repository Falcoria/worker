from celery import Celery
from kombu import Exchange, Queue

from app.config import config
from app.constants.task_names import TaskNames
from app.runtime.ip_initializer import register_worker_ip


celery_app = Celery(config.celery_app_name, broker=config.ampq_connection_str)
app_exchange = Exchange(config.exchange_name, type=config.exchange_type)

celery_app.conf.task_queues = [
    Queue(
        name=config.nmap_scan_queue_name,
        exchange=app_exchange,
        routing_key=config.nmap_scan_routing_key,
    ),
    Queue(
        name=config.nmap_cancel_queue_name,
        exchange=app_exchange,
        routing_key=config.nmap_cancel_routing_key,
    ),
]


celery_app.conf.task_routes = {
    TaskNames.PROJECT_SCAN: {
        "queue": config.nmap_scan_queue_name,
        "routing_key": config.nmap_scan_routing_key,
    },
    TaskNames.PROJECT_CANCEL: {
        "queue": config.nmap_cancel_queue_name,
        "routing_key": config.nmap_cancel_routing_key,
    },
}


celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True