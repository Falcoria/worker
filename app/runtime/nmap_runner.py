import os
import tempfile
from typing import Optional, List, Dict

from libnmap.objects.report import NmapReport
from libnmap.parser import NmapParser, NmapParserException

from .command_executor import OsCommandExecutor

from app.config import config


class NmapRunner:
    def __init__(self, executor: OsCommandExecutor):
        self.executor = executor
        self.output_file: Optional[str] = None

    def _build_command(self, target: str, options: str) -> List[str]:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
        self.output_file = tmp.name
        tmp.close()
        return ["nmap"] + options.split() + ["-oX", self.output_file, target]

    def run_open_ports_foreground(
            self, 
            target: str, 
            options: str = config.nmap_open_ports_opts
        ) -> bool:
        return self.executor.run_foreground(self._build_command(target, options))

    def run_open_ports_background(
            self, 
            target: str, 
            options: str = config.nmap_open_ports_opts
        ) -> None:
        self.executor.run_background(self._build_command(target, options))

    def run_service_scan_foreground(
            self, 
            target: str, 
            ports: List[int], 
            base_options: str = config.nmap_service_opts
        ) -> bool:
        port_str = ",".join(map(str, ports))
        options = f"-p {port_str} {base_options}"
        return self.executor.run_foreground(self._build_command(target, options))

    def run_service_scan_background(
            self, 
            target: str, 
            ports: List[int], 
            base_options: str = config.nmap_service_opts
        ) -> None:
        port_str = ",".join(map(str, ports))
        options = f"-p {port_str} {base_options}"
        self.executor.run_background(self._build_command(target, options))

    def is_running(self) -> bool:
        return self.executor.is_running()

    def wait(self, timeout: Optional[int] = None):
        self.executor.wait(timeout)

    def terminate(self):
        self.executor.terminate()

    def parse_output(self) -> Optional[NmapReport]:
        if not self.output_file or not os.path.exists(self.output_file):
            return None
        try:
            return NmapParser.parse_fromfile(self.output_file)
        except (NmapParserException, Exception):
            return None

    def read_output(self) -> Optional[str]:
        if not self.output_file or not os.path.exists(self.output_file):
            return None
        with open(self.output_file, "r") as f:
            return f.read()

    @staticmethod
    def get_open_ports_single_host(report: NmapReport) -> List[int]:
        if len(report.hosts) != 1:
            raise ValueError("Expected exactly one host in the report.")
        host = report.hosts[0]
        return [port for port, _ in host.get_open_ports()]

    @staticmethod
    def get_port_service_map_single_host(report: NmapReport) -> Dict[int, str]:
        if len(report.hosts) != 1:
            raise ValueError("Expected exactly one host in the report.")
        host = report.hosts[0]
        return {service.port: service.service for service in host.services}

    def cleanup(self):
        if self.output_file and os.path.exists(self.output_file):
            os.remove(self.output_file)

    def __del__(self):
        self.cleanup()
