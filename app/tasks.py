import time
import socket

from app.logger import logger
from app.celery_app import celery_app
from app.redis_client import redis_client
from falcoria_common.schemas.enums.celery_routes import NmapTasks, WorkerTasks
from app.runtime.redis_wrappers import RedisNmapWrapper, RedisProcessKiller, RedisTaskTracker, RedisWorkerCleaner
from app.runtime.update_ip import register_worker_ip
from app.initializers import init_worker_ip
from app.config import config
from falcoria_common.schemas.nmap import RunningNmapTarget, NmapTask


init_worker_ip()


@celery_app.task(name=NmapTasks.NMAP_SCAN, bind=True)
def scan_task(self, data):
    task = NmapTask(**data)
    logger.info(f"Received scan task for {task.ip} in project {task.project}")

    tracker = RedisTaskTracker(str(task.project), "nmap")
    wrapper = RedisNmapWrapper(str(task.project))
    task_id = self.request.id

    try:
        target_metadata = RunningNmapTarget(
            ip=task.ip,
            hostnames=task.hostnames,
            worker=config.hostname,
            started_at=int(time.time()),
        )

        tracker.store_running_target(task_id, target_metadata)

        logger.info(f"Starting 2-phase scan with Redis tracking for {task.ip}")
        wrapper.run_two_phase_background(
            target=task.ip,
            hostnames=task.hostnames,
            open_ports_opts=task.open_ports_opts,
            service_opts=task.service_opts,
            timeout=task.timeout,
            include_services=task.include_services,
            mode=task.mode,
            task_id=task_id
        )
    finally:
        # Guaranteed to run
        cleaner = RedisWorkerCleaner(config.hostname, "nmap")
        cleaner.cleanup_task(
            task_id=task_id, 
            project_id=str(task.project),
            user_id=str(task.user.id),
            ip=task.ip,
            port_string=task.open_ports_str
        )
        tracker.release_ip_lock(task.ip)

        logger.info(f"Removed IP {task.ip} from project:{task.project}:ip_task_map (via finally)")


@celery_app.task(name=NmapTasks.NMAP_CANCEL, bind=True)
def cancel_task(self, data):
    task_ids = data.get("task_ids", [])
    
    killer = RedisProcessKiller("nmap")
    killer.kill_by_task_ids(task_ids)

    # Optional: clean up any stale lock
    redis_client.delete(f"scan:lock:{socket.gethostname()}")


@celery_app.task(name=WorkerTasks.UPDATE_WORKER_IP)
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