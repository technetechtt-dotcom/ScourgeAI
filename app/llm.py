"""Language-model gate. Calls stay refused.

Grounding, permission checks, evaluation, and audit controls are not verified,
so there is no provider client in this process.
"""
from __future__ import annotations


class LLMDisabled(RuntimeError):
    pass


def complete(_prompt: str, evidence_ids: list[str]) -> str:
    if not evidence_ids:
        raise LLMDisabled("A language model call requires stored evidence identifiers, and calls are disabled.")
    raise LLMDisabled(
        "Language model calls are disabled until grounding, permissions, evaluation, and audit controls are verified."
    )
