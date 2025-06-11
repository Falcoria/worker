from uuid import UUID
from enum import Enum

from typing import List

from pydantic import BaseModel, Field


class ImportMode(str, Enum):
    INSERT = "insert"
    REPLACE = "replace"
    UPDATE = "update"
    APPEND = "append"


class NmapTask(BaseModel):
    ip: str
    hostnames: List[str] = Field(
        default_factory=list,
        description="List of hostnames associated with the target IP"
    )
    project: UUID
    open_ports_opts: str
    service_opts: str
    timeout: int
    include_services: bool
    mode: ImportMode