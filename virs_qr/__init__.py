"""Virs QR Code Generator.

This package provides QR code generation utilities with input validation for
ethical security testing and demos.
"""

from .security import is_malicious_request, validate_payload
from .templates import TEMPLATES, build_payload

__all__ = [
    "is_malicious_request",
    "validate_payload",
    "TEMPLATES",
    "build_payload",
]

try:
    from .generator import QRConfig, generate_qr, qr_to_ascii

    __all__.extend(["QRConfig", "generate_qr", "qr_to_ascii"])
except ModuleNotFoundError:
    # Allows importing the package in environments where optional deps
    # (e.g. qrcode/Pillow) are not installed yet.
    pass
