import socket

from celery import shared_task
from celery.signals import task_postrun

from app.logger import logger
from app.celery_app import celery_app
from app.redis_client import redis_client
from app.constants.task_names import TaskNames
from app.constants.task_schemas import NmapTask
from app.runtime.redis_wrappers import RedisNmapWrapper, RedisProcessKiller, RedisTaskTracker 
from app.runtime.ip_initializer import register_worker_ip
from app.initializers import init_worker_ip


init_worker_ip()


@celery_app.task(name=TaskNames.PROJECT_SCAN, bind=True)
def scan_task(self, data):
    task = NmapTask(**data)
    logger.info(f"Received scan task for {task.ip} in project {task.project}")

    wrapper = RedisNmapWrapper(redis_client=redis_client, project=task.project)
    logger.info(f"Starting 2-phase scan with Redis tracking for {task.ip}")
    wrapper.run_two_phase_background(
        target=task.ip,
        open_ports_opts=task.open_ports_opts,
        service_opts=task.service_opts,
        timeout=task.timeout,
    )


@celery_app.task(name=TaskNames.PROJECT_CANCEL, bind=True)
def cancel_task(self, data):
    #project = data.get("project")
    project = data
    logger.info(f"Cancel requested for project: {project}")
    
    killer = RedisProcessKiller(redis_client, project)
    killer.kill_all_for_project()

    # Optional: clean up any stale lock
    redis_client.delete(f"scan:lock:{socket.gethostname()}")


@task_postrun.connect
def cleanup_task_id(sender=None, task_id=None, task=None, args=None, kwargs=None, **extras):
    if sender and sender.name == TaskNames.PROJECT_SCAN and args:
        data = args[0]
        if isinstance(data, dict):
            project = data.get("project")
            if project:
                logger.info(f"Removing task_id {task_id} for project {project}")
                tracker = RedisTaskTracker(redis_client, project)
                tracker.remove_task_id(task_id)