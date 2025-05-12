from uuid import UUID
import requests
import urllib3

from app.config import config
from app.logger import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScanledgerConnector:
    def __init__(self):
        self.server_url = config.backend_base_url.rstrip('/')
        self.auth_token = config.worker_backend_token
        logger.debug(f"BackendConnector initialized with server URL: {self.server_url} and auth token: {self.auth_token}")
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for the whole session

    def make_request(
            self, 
            url: str, 
            headers: dict = None, 
            method: str = "GET", 
            data=None, 
            timeout: int = 20, 
            files=None):
        """Make synchronous HTTP request"""
        headers = headers or {}
        headers["Authorization"] = f"Bearer {self.auth_token}"

        logger.debug(f"Making {method} request to {url} with headers: {headers} and data: {data}")

        try:
            if method in ["GET", "DELETE"]:
                response = self.session.request(method, url, headers=headers, params=data, timeout=timeout)
            elif files is not None:
                response = self.session.post(url, headers=headers, files=files, timeout=timeout)
            elif method in ["POST", "PUT"]:
                response = self.session.request(method, url, headers=headers, json=data, timeout=timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            return response
        except requests.RequestException as e:
            logger.error(f"Request error in BackendConnector.make_request: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in BackendConnector.make_request: {e}")
            return None

    @staticmethod
    def process_response(response: requests.Response):
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error("Resource not found (404).")
        elif response.status_code == 401:
            logger.error("Unauthorized access (401).")
        else:
            logger.error(f"Unexpected status: {response.status_code}")
        return None

    def upload_nmap_report(self, project: UUID, report: str):
        url = f"{self.server_url}/projects/{project}/ips/import"

        files = {
            "file": ("nmap_report.xml", report, "text/xml")
        }

        response = self.make_request(
            url=url,
            method="POST",
            files=files,
        )

        if response is None:
            logger.error("No response received from backend.")
            return None

        return self.process_response(response)
