from __future__ import annotations


def shown(text: str, limit: int = 120) -> str:
    """Project-supplied text, escaped so it cannot drive the terminal, and cut to a sane length."""
    return repr(text[:limit]) + ("..." if len(text) > limit else "")
