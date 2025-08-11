import os
import tempfile
from typing import Optional, List, Dict
import xml.etree.ElementTree as ET

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

    def run_open_ports_background(
            self, 
            target: str, 
            options: str = config.nmap_open_ports_opts
        ) -> None:
        self.executor.run_background(self._build_command(target, options))

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
    def enrich_nmap_report(
        base_xml_path: str,
        service_xml_path: Optional[str],
        target_ip: str,
        hostnames: List[str]
    ) -> Optional[str]:
        """
        Enriches Nmap base XML report with:
        1. Hostnames for the given IP
        2. Service metadata (from optional second scan)
        
        Returns modified XML string.
        """
        if not os.path.exists(base_xml_path):
            return None

        with open(base_xml_path, "r") as f:
            base_tree = ET.ElementTree(ET.fromstring(f.read()))
        base_root = base_tree.getroot()

        # Step 1: Inject hostnames
        for host in base_root.findall("host"):
            addr_elem = host.find("address")
            if addr_elem is not None and addr_elem.attrib.get("addr") == target_ip:
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is None:
                    hostnames_elem = ET.SubElement(host, "hostnames")
                else:
                    hostnames_elem.clear()

                for hname in hostnames:
                    ET.SubElement(
                        hostnames_elem, "hostname",
                        attrib={"name": hname, "type": "user"}
                    )

        # Step 2: Inject service data
        if service_xml_path and os.path.exists(service_xml_path):
            with open(service_xml_path, "r") as f:
                service_tree = ET.ElementTree(ET.fromstring(f.read()))
            service_root = service_tree.getroot()

            # Build lookup for services by (ip, portid, protocol)
            service_map = {}
            for host in service_root.findall("host"):
                addr_elem = host.find("address")
                if addr_elem is None:
                    continue
                ip = addr_elem.attrib.get("addr")
                for port in host.findall(".//port"):
                    key = (ip, port.attrib.get("portid"), port.attrib.get("protocol"))
                    service_map[key] = port

            # Inject into base
            for host in base_root.findall("host"):
                addr_elem = host.find("address")
                if addr_elem is None:
                    continue
                ip = addr_elem.attrib.get("addr")
                for port in host.findall(".//port"):
                    key = (ip, port.attrib.get("portid"), port.attrib.get("protocol"))
                    service_port = service_map.get(key)
                    if not service_port:
                        continue

                    # Clean old <service> and <script>
                    for tag in ["service", "script"]:
                        old_tag = port.find(tag)
                        if old_tag is not None:
                            port.remove(old_tag)
                        new_tag = service_port.find(tag)
                        if new_tag is not None:
                            port.append(new_tag)

        return ET.tostring(base_root, encoding="utf-8", xml_declaration=True).decode("utf-8")

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
