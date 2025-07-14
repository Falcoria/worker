from uuid import UUID
import requests
import urllib3

from app.config import config
from app.logger import logger
#from app.constants.task_schemas import ImportMode
from falcoria_common.schemas.enums import ImportMode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScanledgerConnector:
    def __init__(self):
        self.server_url = config.backend_base_url.rstrip('/')
        self.auth_token = config.worker_backend_token
        logger.debug(f"BackendConnector initialized with server URL: {self.server_url} and auth token: {self.auth_token}")
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for the whole session
        self.session.headers.update({"Authorization": f"Bearer {self.auth_token}"})

    def make_request(
        self,
        url: str,
        method: str = "GET",
        query_params: dict = None,
        json_body: dict = None,
        timeout: int = 20,
        files=None
    ):
        """Make HTTP request with proper separation of query params and JSON body"""
        try:
            if method in ["GET", "DELETE"]:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=query_params,
                    timeout=timeout
                )
            elif files is not None:
                response = self.session.post(
                    url=url,
                    params=query_params,
                    files=files,
                    data={},
                    timeout=timeout
                )
            elif method in ["POST", "PUT"]:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=query_params,
                    json=json_body,
                    timeout=timeout
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            return response

        except requests.RequestException as e:
            logger.error(f"Request error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
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
            logger.error(f"Unexpected status: {response.status_code} - {response.text}")
        return None

    def upload_nmap_report(self, project_id: str, report: str, mode: ImportMode):
        url = f"{self.server_url}/projects/{project_id}/ips/import"

        files = {
            "file": ("nmap_report.xml", report, "text/xml")
        }

        response = self.make_request(
            url=url,
            method="POST",
            query_params={"mode": mode.value},
            files=files
        )

        if response is None:
            logger.error("No response received from backend.")
            return None

        return self.process_response(response)

    def create_ip(self, project: UUID, query: str = None, ips: list = None):
        url = f"{self.server_url}/projects/{project}/ips"
        response = self.make_request(
            url=url,
            method="POST",
            json_body=ips,
            query_params=query
        )

        if response is None:
            logger.error("No response received from backend.")
            return None
