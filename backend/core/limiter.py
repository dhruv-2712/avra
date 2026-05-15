import os
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return get_remote_address(request)


_redis_url = os.getenv("REDIS_URL")
limiter = Limiter(
    key_func=_get_client_ip,
    **({"storage_uri": _redis_url} if _redis_url else {}),
)
