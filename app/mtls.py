"""Client-certificate gate. Off unless TIC_MTLS_REQUIRED=1.

The certificate must be present on the TLS connection. A request header is not accepted.
"""
from __future__ import annotations

import os

from fastapi.responses import JSONResponse


def mtls_satisfied(scope: dict) -> bool:
    if os.environ.get("TIC_MTLS_REQUIRED") != "1":
        return True
    tls = (scope.get("extensions") or {}).get("tls") or {}
    chain = tls.get("client_cert_chain") or tls.get("client_cert_der")
    return bool(chain)


def mtls_response(scope: dict) -> JSONResponse | None:
    if mtls_satisfied(scope):
        return None
    return JSONResponse({"detail": "Client certificate required"}, status_code=401)
