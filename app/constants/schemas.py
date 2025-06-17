import time

from pydantic import BaseModel, Field


class RunningTarget(BaseModel):
    ip: str
    hostnames: list[str]
    worker: str
    started_at: int = Field(default_factory=lambda: int(time.time()))