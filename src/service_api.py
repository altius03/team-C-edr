from __future__ import annotations

import socket
from socketserver import ThreadingMixIn
from typing import TypeAlias

import uvicorn

from .api_app import create_app
from .api_models import ApiSettings
from .service_store import ServiceStore
from .task_queue import TaskQueue

ServerAddress: TypeAlias = tuple[str, int]


class FastApiServiceServer(ThreadingMixIn):
    daemon_threads = True

    def __init__(
        self,
        address: ServerAddress,
        store: ServiceStore,
        *,
        task_queue: TaskQueue | None = None,
        settings: ApiSettings | None = None,
    ) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(address)
        self._socket.listen(socket.SOMAXCONN)
        self.server_address = self._socket.getsockname()
        app = create_app(store, task_queue=task_queue, settings=settings)
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=self.server_address[0],
                port=self.server_address[1],
                log_level="warning",
                lifespan="on",
            )
        )

    def serve_forever(self) -> None:
        self._server.run(sockets=[self._socket])

    def shutdown(self) -> None:
        self._server.should_exit = True

    def server_close(self) -> None:
        try:
            self._socket.close()
        except OSError:
            return


def create_service_server(
    address: ServerAddress,
    store: ServiceStore,
    *,
    task_queue: TaskQueue | None = None,
    settings: ApiSettings | None = None,
) -> FastApiServiceServer:
    return FastApiServiceServer(address, store, task_queue=task_queue, settings=settings)
