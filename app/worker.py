"""Outbox workers. Disabled unless TIC_WORKER=1. Claims are safe across processes."""
from __future__ import annotations

import logging
import os
import threading
import uuid

from .db import SessionLocal
from .outbox import process_outbox

logger = logging.getLogger("scourgeai.worker")


def start_worker():
    """Start one or more claim workers. Another process can run the same loop safely."""
    if os.environ.get("TIC_WORKER") != "1":
        return None
    stop = threading.Event()
    interval = int(os.environ.get("TIC_WORKER_INTERVAL", "5"))
    copies = max(1, int(os.environ.get("TIC_WORKER_COUNT", "1")))

    def loop(worker_id: str) -> None:
        while not stop.wait(interval):
            try:
                with SessionLocal() as db:
                    process_outbox(db, worker_id=worker_id)
            except Exception:
                logger.exception("outbox worker failed")

    for _ in range(copies):
        worker_id = uuid.uuid4().hex[:12]
        threading.Thread(target=loop, args=(worker_id,), name=f"outbox-{worker_id}", daemon=True).start()
    return stop
