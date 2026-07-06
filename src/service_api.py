from __future__ import annotations

import os
from socketserver import ThreadingMixIn
from typing import TypeAlias
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from django.core.handlers.wsgi import WSGIHandler

from .django_backend.state import set_store
from .service_store import ServiceStore

ServerAddress: TypeAlias = tuple[str, int]


class ThreadingDjangoServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietDjangoRequestHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


def create_service_server(address: ServerAddress, store: ServiceStore) -> WSGIServer:
    """Create the local API server using Django's WSGI request stack.

    The public factory stays stable for tests and scripts, while URL routing,
    request parsing, and JSON responses now live in the Django app under
    src.django_backend.
    """

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "src.django_backend.settings")

    import django

    django.setup()
    set_store(store)
    return make_server(
        address[0],
        address[1],
        WSGIHandler(),
        server_class=ThreadingDjangoServer,
        handler_class=QuietDjangoRequestHandler,
    )
