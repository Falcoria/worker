from enum import Enum


class TaskNames(str, Enum):
    PROJECT_SCAN = "project.nmap.scan"
    PROJECT_CANCEL = "project.nmap.cancel"
    UPDATE_WORKER_IP = "worker.update_ip"