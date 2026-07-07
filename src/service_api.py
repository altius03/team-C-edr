"""Run the FastAPI app inside tests and local scripts through a small server wrapper."""

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
    """Own the listening socket and delegate request handling to Uvicorn."""

    daemon_threads = True

    def __init__(
        self,
        address: ServerAddress,
        store: ServiceStore,
        *,
        task_queue: TaskQueue | None = None,
        settings: ApiSettings | None = None,
    ) -> None:
        """Bind the requested address before handing the socket to Uvicorn."""

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
        """Run the configured ASGI server until shutdown is requested."""

        self._server.run(sockets=[self._socket])

    def shutdown(self) -> None:
        """Ask Uvicorn to exit its serving loop."""

        self._server.should_exit = True

    def server_close(self) -> None:
        """Close the owned listening socket, ignoring already-closed sockets."""

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
    """Create the service server used by scripts and compatibility tests."""

    return FastApiServiceServer(address, store, task_queue=task_queue, settings=settings)
