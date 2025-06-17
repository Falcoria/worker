import os
import signal
import errno
import socket
import json
import redis
import time

from .nmap_runner import NmapRunner
from .command_executor import OsCommandExecutor
from .scanledger_connector import ScanledgerConnector

from app.logger import logger
from app.constants.task_schemas import ImportMode
from app.constants.schemas import RunningTarget


def get_project_pids_key(project: str) -> str:
    return f"project:{project}:pids"


def get_project_ip_task_map_key(project: str) -> str:
    return f"project:{project}:ip_task_map"


class RedisTaskTracker:
    def __init__(self, redis_client: redis.Redis, project_id: str):
        self.redis = redis_client
        self.project = project_id
        self.ip_task_map_key = get_project_ip_task_map_key(project_id)

    def track_ip_task(self, ip: str, task_id: str):
        """Track IP → task_id."""
        self.redis.hset(self.ip_task_map_key, ip, task_id)

    def get_ip_task_map(self):
        """Return IP → task_id map."""
        return self.redis.hgetall(self.ip_task_map_key)

    def remove_ip_task(self, ip: str):
        """Remove entry for IP."""
        self.redis.hdel(self.ip_task_map_key, ip)

    def acquire_ip_lock(self, ip: str, ttl_seconds: int = 300) -> bool:
        """Acquire a Redis lock for an IP."""
        key = f"project:{self.project}:ip_task_lock:{ip}"
        was_set = self.redis.set(key, "1", ex=ttl_seconds, nx=True)
        return was_set is True

    def release_ip_lock(self, ip: str):
        """Release the Redis lock for an IP."""
        key = f"project:{self.project}:ip_task_lock:{ip}"
        self.redis.delete(key)

    def _running_targets_key(self):
        return f"project:{self.project}:running_targets"
    
    def store_running_target(self, target: RunningTarget):
        key = self._running_targets_key()
        value = target.model_dump_json()
        self.redis.rpush(key, value)

    def remove_running_target(self, ip: str, worker: str):
            key = self._running_targets_key()
            running = self.redis.lrange(key, 0, -1)
            for entry in running:
                data = json.loads(entry.decode() if isinstance(entry, bytes) else entry)
                if data["ip"] == ip and data.get("worker") == worker:
                    self.redis.lrem(key, 0, entry)
                    break


class RedisNmapWrapper:
    def __init__(self, redis_client: redis.Redis, project: str):
        self.redis = redis_client
        self.project = project
        self.hostname = socket.gethostname()
        self.key = get_project_pids_key(project)

    def _store_pid(self, pid: int):
        entry = json.dumps({"pid": pid, "host": self.hostname})
        self.redis.rpush(self.key, entry)

    def _remove_pid(self, pid: int):
        entry = json.dumps({"pid": pid, "host": self.hostname})
        self.redis.lrem(self.key, 0, entry)

    def run_two_phase_background(
        self, 
        target: str, 
        hostnames: list,
        open_ports_opts: str, 
        service_opts: str, 
        timeout: int, 
        include_services: bool,
        mode: ImportMode
    ):
        # TODO: add try except finally
        scanledger_connector = ScanledgerConnector()

        # Phase 1: Open ports
        executor1 = OsCommandExecutor(timeout=timeout)
        nmap1 = NmapRunner(executor1)

        nmap1.run_open_ports_background(target, open_ports_opts)
        self._store_pid(executor1.process.pid)
        nmap1.wait()
        self._remove_pid(executor1.process.pid)

        report = nmap1.parse_output()
        if not report:
            logger.error("Failed to parse report from open ports phase.")
            return

        ports = nmap1.get_open_ports_single_host(report)

        # Always inject hostnames and upload Phase 1, even if no ports
        modified_nmap1_xml = nmap1.inject_hostnames_into_output(target, hostnames)

        if not ports:
            logger.info(f"No open ports found for target {target}. Uploading Phase 1 report with hostnames.")
            scanledger_connector.upload_nmap_report(self.project, modified_nmap1_xml, mode)
            return

        if not include_services:
            logger.info(f"Open ports found: {ports}. Uploading Phase 1 report with hostnames only.")
            scanledger_connector.upload_nmap_report(self.project, modified_nmap1_xml, mode)
            return

        # Phase 2: Service scan
        executor2 = OsCommandExecutor(timeout=timeout)
        nmap2 = NmapRunner(executor2)

        logger.info(f"Running service scan on ports: {ports}")
        nmap2.run_service_scan_background(target, ports, service_opts)
        self._store_pid(executor2.process.pid)
        nmap2.wait()
        self._remove_pid(executor2.process.pid)

        logger.info(f"Two-phase scan completed for {target}.")

        # Upload Phase 2 result with hostnames
        modified_nmap2_xml = nmap2.inject_hostnames_into_output(target, hostnames)
        scanledger_connector.upload_nmap_report(self.project, modified_nmap2_xml, mode)

        # Upload Phase 1 result again in APPEND mode → ensures Phase 1 ports preserved
        scanledger_connector.upload_nmap_report(self.project, modified_nmap1_xml, ImportMode.APPEND)


class RedisProcessKiller:
    def __init__(self, redis_client: redis.Redis, project: str):
        self.redis = redis_client
        self.project = project
        self.hostname = socket.gethostname()
        self.key = get_project_pids_key(project)

    def kill_all_for_project(self):
        entries = self.redis.lrange(self.key, 0, -1)

        for entry in entries:
            info = self._parse_entry(entry)
            if not info:
                continue

            if info["host"] != self.hostname:
                continue

            logger.info(f"Terminating process on {self.hostname} with PID {info['pid']}")
            self._terminate_pid(info["pid"], entry)

    def _parse_entry(self, entry) -> dict:
        try:
            if isinstance(entry, bytes):
                entry = entry.decode()

            info = json.loads(entry)

            if not isinstance(info, dict) or "host" not in info or "pid" not in info:
                logger.warning(f"Skipping malformed entry: {entry}")
                return None

            return info

        except Exception as e:
            logger.error(f"Failed to parse entry: {entry}. Error: {e}")
            return None

    def _terminate_pid(self, pid: int, entry: str):
        logger.info(f"Attempting to kill PID {pid} on {self.hostname}")
        try:
            if self._is_pid_alive(pid):
                os.kill(pid, signal.SIGTERM)
                logger.info(f"SIGTERM sent to PID {pid}")
            else:
                logger.warning(f"Process {pid} already exited.")
        except Exception as e:
            logger.error(f"Error while killing PID {pid}: {e}")
        finally:
            self.redis.lrem(self.key, 0, entry)

    def _is_pid_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            return e.errno != errno.ESRCH
