import subprocess
from typing import Optional, List

from app.logger import logger


class OsCommandExecutor:
    def __init__(self, timeout: Optional[int] = None):
        self.command: Optional[List[str]] = None
        self.timeout = timeout
        self.process: Optional[subprocess.Popen] = None
        self.output: Optional[str] = None
        self.error: Optional[str] = None
        self.return_code: Optional[int] = None

    def run_foreground(self, command: List[str]) -> bool:
        self.command = command
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout
            )
            self.output = result.stdout
            self.error = result.stderr
            self.return_code = result.returncode
            return result.returncode == 0
        except subprocess.TimeoutExpired as e:
            self.output = e.stdout
            self.error = "Timeout expired"
            self.return_code = -1
            return False
        except Exception as e:
            self.error = str(e)
            self.return_code = -1
            return False

    def run_background(self, command: List[str]):
        self.command = command
        logger.debug(f"Running command: {command}")
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def wait(self, timeout: Optional[int] = None):
        effective_timeout = timeout or self.timeout
        if self.process:
            try:
                self.process.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                self.terminate()

    def terminate(self):
        if self.process and self.is_running():
            logger.info(f"Terminating process: {self.process.pid}")
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.output, self.error = self.process.communicate()
            self.return_code = self.process.returncode

    def get_stdout(self) -> Optional[str]:
        return self.output

    def get_stderr(self) -> Optional[str]:
        return self.error

    def get_return_code(self) -> Optional[int]:
        return self.return_code
