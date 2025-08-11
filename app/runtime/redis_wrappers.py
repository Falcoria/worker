import os
import json
import errno
import signal


from app.logger import logger
from app.config import config
from falcoria_common.schemas.enums.common import ImportMode
from falcoria_common.schemas.nmap import RunningNmapTarget
from .nmap_runner import NmapRunner
from .command_executor import OsCommandExecutor
from .scanledger_connector import ScanledgerConnector
from falcoria_common.redis.redis_keys import RedisKeyBuilder
from falcoria_common.redis.redis_task_tracker import BaseRedisTracker
from app.redis_client import redis_client


def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        return e.errno != errno.ESRCH


def _terminate_pid(pid: int, hostname: str):
    logger.info(f"Attempting to kill PID {pid} on {hostname}")
    if _is_pid_alive(pid):
        os.kill(pid, signal.SIGTERM)
        logger.info(f"SIGTERM sent to PID {pid}")
    else:
        logger.warning(f"Process {pid} already exited.")


class RedisTaskTracker(BaseRedisTracker):
    def __init__(self, project: str, tool: str):
        self.project = project
        self.tool = tool
        self.hostname = config.hostname
        self.redis = redis_client
        self.hash_key = f"running_tool:{tool}:{self.hostname}"

    def store_running_target(self, task_id: str, target: RunningNmapTarget):
        key = RedisKeyBuilder.running_tasks_key(task_id, self.hostname)
        value = target.model_dump_json()
        self.redis.rpush(key, value)

    def delete_running_task_entry(self, task_id: str):
        key = RedisKeyBuilder.running_tasks_key(task_id, self.hostname)
        self.redis.delete(key)

    def remove_running_target(self, ip: str, worker: str):
        key = RedisKeyBuilder.running_targets_key(self.project)
        running = self.redis.lrange(key, 0, -1)
        for entry in running:
            data = json.loads(entry.decode() if isinstance(entry, bytes) else entry)
            if data.get("ip") == ip and data.get("worker") == worker:
                self.redis.lrem(key, 0, entry)
                break

    def track_pid_entry(self, pid: int, task_id: str):
        self.redis.hset(self.hash_key, task_id, pid)

    def remove_pid_entry(self, task_id: str):
        self.redis.hdel(self.hash_key, task_id)

    def get_pid_for_task(self, task_id: str):
        pid = self.redis.hget(self.hash_key, task_id)
        return int(pid) if pid else None


class RedisNmapWrapper:
    def __init__(self, project: str):
        self.project = project
        self.hostname = config.hostname
        self.tool = "nmap"
        self.redis_tracker = RedisTaskTracker(project, self.tool)

    def run_two_phase_background(
        self,
        target: str,
        hostnames: list,
        open_ports_opts: str,
        service_opts: str,
        timeout: int,
        include_services: bool,
        mode: ImportMode,
        task_id: str
    ):
        scanledger_connector = ScanledgerConnector()

        # Phase 1: Port scan
        executor1 = OsCommandExecutor(timeout=timeout)
        nmap1 = NmapRunner(executor1)

        nmap1.run_open_ports_background(target, open_ports_opts)
        self.redis_tracker.track_pid_entry(pid=executor1.process.pid, task_id=task_id)
        nmap1.wait()
        self.redis_tracker.remove_pid_entry(task_id)

        report = nmap1.parse_output()
        if not report:
            logger.error("Failed to parse report from open ports phase.")
            return

        open_ports = nmap1.get_open_ports_single_host(report)
        if not open_ports:
            logger.info(f"No open ports found for target {target}. Uploading base scan with hostnames.")
            final_xml = nmap1.enrich_nmap_report(
                base_xml_path=nmap1.output_file,
                service_xml_path=None,
                target_ip=target,
                hostnames=hostnames
            )
            scanledger_connector.upload_nmap_report(self.project, final_xml, mode)
            return

        if not include_services:
            logger.info(f"Open ports found: {open_ports}. Uploading base scan without service enrichment.")
            final_xml = nmap1.enrich_nmap_report(
                base_xml_path=nmap1.output_file,
                service_xml_path=None,
                target_ip=target,
                hostnames=hostnames
            )
            scanledger_connector.upload_nmap_report(self.project, final_xml, mode)
            return

        # Phase 2: Service scan on open ports only
        executor2 = OsCommandExecutor(timeout=timeout)
        nmap2 = NmapRunner(executor2)

        logger.info(f"Running service scan on ports: {open_ports}")
        nmap2.run_service_scan_background(target, open_ports, service_opts)

        self.redis_tracker.track_pid_entry(pid=executor2.process.pid, task_id=task_id)
        nmap2.wait()
        self.redis_tracker.remove_pid_entry(task_id)

        logger.info(f"Two-phase scan completed for {target}. Uploading merged result.")

        # Merge phase 1 + phase 2 results into one enriched XML
        final_xml = nmap1.enrich_nmap_report(
            base_xml_path=nmap1.output_file,
            service_xml_path=nmap2.output_file,
            target_ip=target,
            hostnames=hostnames
        )
        scanledger_connector.upload_nmap_report(self.project, final_xml, mode)


class RedisProcessKiller:
    def __init__(self, tool: str):
        self.hostname = config.hostname
        self.tool = tool
        self.redis = RedisTaskTracker(config.hostname, "nmap")
        self.hash_key = RedisKeyBuilder.running_tool_key(self.tool, self.hostname)

    def kill_by_task_ids(self, task_ids: list[str]):
        if not task_ids:
            return

        for task_id in task_ids:
            pid = self.redis.get_pid_for_task(task_id)
            if pid is None:
                continue
            try:
                _terminate_pid(pid, self.hostname)
                
            except Exception as e:
                logger.error(f"Failed to terminate PID for task_id={task_id}: {e}")


class RedisWorkerCleaner:
    def __init__(self, hostname: str, tool: str):
        self.redis = redis_client
        self.hostname = hostname
        self.tool = tool

    def cleanup_task(self, task_id: str, project_id: str, user_id: str, ip: str, port_string: str):
        logger.info(f"Cleaning up Redis records for task {task_id}")

        # Build Redis keys
        hash_key = RedisKeyBuilder.running_tool_key(self.tool, self.hostname)
        running_task_key = RedisKeyBuilder.running_tasks_key(task_id, self.hostname)
        project_key = RedisKeyBuilder.project_task_ids_key(project_id)
        user_key = RedisKeyBuilder.user_task_ids_key(user_id)
        ip_key = RedisKeyBuilder.project_ip_task_ids_key(project_id, ip)
        meta_key = RedisKeyBuilder.task_metadata_nmap_key(task_id) 

        # Determine lock key
        lock_key = RedisKeyBuilder.lock_ip_ports_key(project_id, ip, port_string)

        # Start pipeline to delete all related entries atomically
        pipe = self.redis.pipeline()
        pipe.hdel(hash_key, task_id)
        pipe.delete(running_task_key)
        pipe.srem(project_key, task_id)
        pipe.srem(user_key, task_id)
        pipe.srem(ip_key, task_id)
        pipe.delete(lock_key)
        pipe.delete(meta_key)
        pipe.execute()

        logger.info(f"Redis cleanup completed for task {task_id}")