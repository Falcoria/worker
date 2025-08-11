from celery import Celery
from kombu import Exchange, Queue, Connection
from kombu.common import Broadcast

from app.config import config
from falcoria_common.schemas.enums.celery_routes import NmapTasks, WorkerTasks


celery_app = Celery(config.celery_app_name, broker=config.ampq_connection_str)
app_exchange = Exchange(config.exchange_name, type=config.exchange_type)

celery_app.conf.task_queues = [
    Queue(
        name=config.nmap_scan_queue_name,
        exchange=app_exchange,
        routing_key=config.nmap_scan_routing_key,
    ),
    Broadcast(
        name=config.nmap_cancel_queue_name
    ),
    Broadcast(
        name=config.worker_service_broadcast_queue,
    )
]


with Connection(config.ampq_connection_str) as conn:
    for name in [config.nmap_cancel_queue_name, config.worker_service_broadcast_queue]:
        Broadcast(name=name).exchange(conn).declare()


celery_app.conf.task_routes = {
    NmapTasks.NMAP_SCAN: {
        "queue": config.nmap_scan_queue_name,
        "routing_key": config.nmap_scan_routing_key,
    },
    NmapTasks.NMAP_CANCEL: {
        "queue": config.nmap_cancel_queue_name,
    },
    WorkerTasks.UPDATE_WORKER_IP: {
        "queue": config.worker_service_broadcast_queue,
    },
}

celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True
celery_app.conf.timezone = 'UTC'