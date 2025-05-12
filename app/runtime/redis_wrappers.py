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


def get_project_pids_key(project: str) -> str:
    return f"project:{project}:pids"


def get_project_task_ids_key(project: str) -> str:
    return f"project:{project}:task_ids"


class RedisTaskTracker:
    def __init__(self, redis_client: redis.Redis, project: str):
        self.redis = redis_client
        self.project = project
        self.key = get_project_task_ids_key(project)

    def remove_task_id(self, task_id: str):
        self.redis.lrem(self.key, 0, task_id)


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

    def run_two_phase_background(self, target: str, open_ports_opts: str, service_opts: str, timeout: int):
        # Phase 1: Open ports
        executor1 = OsCommandExecutor(timeout=timeout)
        nmap1 = NmapRunner(executor1)
        nmap1.run_open_ports_background(target, open_ports_opts)
        self._store_pid(executor1.process.pid)
        nmap1.wait()
        self._remove_pid(executor1.process.pid)

        # check for errors
        # TODO: if error -> send to backend with message
        # TODO: enum for error codes

        report = nmap1.parse_output()
        if not report:
            logger.error("Failed to parse report from open ports phase.")
            return

        ports = nmap1.get_open_ports_single_host(report)
        if not ports:
            logger.error(f"No open ports found for the target. {target}")
            return

        # Phase 2: Service scan
        executor2 = OsCommandExecutor(timeout=timeout)
        nmap2 = NmapRunner(executor2)
        nmap2.run_service_scan_background(target, ports, service_opts)
        self._store_pid(executor2.process.pid)
        nmap2.wait()
        self._remove_pid(executor2.process.pid)

        logger.info(f"Two-phase scan completed for {target}.")

        backend_connector = ScanledgerConnector()
        backend_connector.upload_nmap_report(self.project, nmap2.read_output())


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

            self._terminate_pid(info["pid"], entry)

    def _parse_entry(self, entry) -> dict:
        try:
            if isinstance(entry, bytes):
                entry = entry.decode()

            info = json.loads(entry)

            if not isinstance(info, dict) or "host" not in info or "pid" not in info:
                #print(f"⚠️ Skipping malformed entry: {entry}")
                logger.warning(f"Skipping malformed entry: {entry}")
                return None

            return info

        except Exception as e:
            #print(f"❌ Failed to parse entry: {entry}. Error: {e}")
            logger.error(f"Failed to parse entry: {entry}. Error: {e}")
            return None

    def _terminate_pid(self, pid: int, entry: str):
        #print(f"⛔ Attempting to kill PID {pid} on {self.hostname}")
        logger.info(f"Attempting to kill PID {pid} on {self.hostname}")
        try:
            if self._is_pid_alive(pid):
                os.kill(pid, signal.SIGTERM)
                logger.info(f"SIGTERM sent to PID {pid}")
            else:
                #print(f"⚠️ Process {pid} already exited.")
                logger.warning(f"Process {pid} already exited.")
        except Exception as e:
            #print(f"❌ Error while killing PID {pid}: {e}")
            logger.error(f"Error while killing PID {pid}: {e}")
        finally:
            self.redis.lrem(self.key, 0, entry)

    def _is_pid_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            return e.errno != errno.ESRCH