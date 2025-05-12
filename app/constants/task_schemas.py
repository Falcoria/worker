from uuid import UUID

from pydantic import BaseModel


class NmapTask(BaseModel):
    ip: str
    project: UUID
    open_ports_opts: str
    service_opts: str
    timeout: int
