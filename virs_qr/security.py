import re
from typing import Iterable

MAX_PAYLOAD_LENGTH = 4096


def _compile_patterns(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_MALICIOUS_PATTERNS = _compile_patterns(
    [
        r"javascript:",
        r"data:text/html",
        r"<\s*script\b",
        r"\bon\w+\s*=",  # onerror=, onclick=, ...
        r"cmd\.exe",
        r"powershell\.exe",
        r"/etc/passwd",
        r"\brm\s+-rf\b",
        r"\bcurl\s+[^\s]+\s*\|\s*sh\b",
    ]
)


def is_malicious_request(data: str) -> bool:
    """Return True if the payload looks exploitative.

    This is a heuristic safeguard intended for demos to avoid accidentally
    generating QR codes containing common exploit patterns.
    """

    if not isinstance(data, str):
        return True

    if len(data) > MAX_PAYLOAD_LENGTH:
        return True

    for pattern in _MALICIOUS_PATTERNS:
        if pattern.search(data):
            return True

    return False


def validate_payload(data: str) -> None:
    if not isinstance(data, str):
        raise TypeError("Payload must be a string")

    if not data.strip():
        raise ValueError("Payload cannot be empty")

    if len(data) > MAX_PAYLOAD_LENGTH:
        raise ValueError(
            f"Payload too large (max {MAX_PAYLOAD_LENGTH} chars, got {len(data)})"
        )

    if is_malicious_request(data):
        raise ValueError("Malicious content detected")
