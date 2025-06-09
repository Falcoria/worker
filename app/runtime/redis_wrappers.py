import os
import signal
import errno
import socket
import json
import redis

from .nmap_runner import NmapRunner
from .command_executor import OsCommandExecutor
from .scanledger_connector import ScanledgerConnector

from app.logger import logger
from app.constants.task_schemas import ImportMode


def get_project_pids_key(project: str) -> str:
    return f"project:{project}:pids"


def get_project_ip_task_map_key(project: str) -> str:
    return f"project:{project}:ip_task_map"


class RedisTaskTracker:
    def __init__(self, redis_client: redis.Redis, project: str):
        self.redis = redis_client
        self.project = project
        self.ip_task_map_key = get_project_ip_task_map_key(project)

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
            open_ports_opts: str, 
            service_opts: str, 
            timeout: int, 
            include_services: bool,
            mode: ImportMode
        ):
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

        scanledger_connector = ScanledgerConnector()

        ports = nmap1.get_open_ports_single_host(report)
        if not ports:
            data = [{"ip": target, "ports": []}]
            query = {"mode": mode.value}
            logger.info(f"No open ports found for the target. {target}")
            scanledger_connector.create_ip(self.project, query=query, ips=data)
            return

        if not include_services:
            logger.info(f"Open ports found: {ports}")
            scanledger_connector.upload_nmap_report(self.project, nmap1.read_output(), mode)
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

        scanledger_connector.upload_nmap_report(self.project, nmap2.read_output(), mode)
        
        # Mode APPEND ensures that open ports discovered in Phase 1 are preserved.
        scanledger_connector.upload_nmap_report(self.project, nmap1.read_output(), ImportMode.APPEND)


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
