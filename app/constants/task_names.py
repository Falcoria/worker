from enum import Enum


class TaskNames(str, Enum):
    PROJECT_SCAN = "project.nmap.scan"
    PROJECT_CANCEL = "project.nmap.cancel"
    WORKER_IP_REFRESH = "worker.ip.refresh"