import socket

from celery.signals import task_postrun

from app.logger import logger
from app.celery_app import celery_app
from app.redis_client import redis_client
from app.constants.task_names import TaskNames
from app.constants.task_schemas import NmapTask
from app.runtime.redis_wrappers import RedisNmapWrapper, RedisProcessKiller, RedisTaskTracker 
from app.runtime.update_ip import register_worker_ip
from app.initializers import init_worker_ip


init_worker_ip()


@celery_app.task(name=TaskNames.PROJECT_SCAN, bind=True)
def scan_task(self, data):
    task = NmapTask(**data)
    logger.info(f"Received scan task for {task.ip} in project {task.project}")

    tracker = RedisTaskTracker(redis_client, task.project)
    wrapper = RedisNmapWrapper(redis_client=redis_client, project=task.project)

    try:
        logger.info(f"Starting 2-phase scan with Redis tracking for {task.ip}")
        wrapper.run_two_phase_background(
            target=task.ip,
            open_ports_opts=task.open_ports_opts,
            service_opts=task.service_opts,
            timeout=task.timeout,
            include_services=task.include_services,
            mode=task.mode
        )
    finally:
        # Guaranteed to run
        tracker.remove_ip_task(task.ip)
        tracker.release_ip_lock(task.ip)
        logger.info(f"Removed IP {task.ip} from project:{task.project}:ip_task_map (via finally)")


@celery_app.task(name=TaskNames.PROJECT_CANCEL, bind=True)
def cancel_task(self, data):
    project = data
    logger.info(f"Cancel requested for project: {project}")
    
    killer = RedisProcessKiller(redis_client, project)
    killer.kill_all_for_project()

    # Optional: clean up any stale lock
    redis_client.delete(f"scan:lock:{socket.gethostname()}")


@celery_app.task(name=TaskNames.UPDATE_WORKER_IP)
def update_worker_ip_task():
    logger.info("Running UPDATE_WORKER_IP task")
    register_worker_ip()
    logger.info("Worker IP registered successfully")


"""
@task_postrun.connect
def cleanup_task_id(sender=None, task_id=None, task=None, args=None, kwargs=None, **extras):
    if sender and sender.name == TaskNames.PROJECT_SCAN and args:
        data = args[0]
        if isinstance(data, dict):
            project = data.get("project")
            ip = data.get("ip")
            if project:
                logger.info(f"Cleaning up IP mapping for project {project}")
                tracker = RedisTaskTracker(redis_client, project)
                if ip:
                    tracker.remove_ip_task(ip)
                    logger.info(f"Removed IP {ip} from project:{project}:ip_task_map")
"""