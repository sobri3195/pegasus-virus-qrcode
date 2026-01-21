from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import qrcode

from .security import validate_payload


@dataclass(frozen=True, slots=True)
class QRConfig:
    version: int | None = None
    error_correction: str = "H"  # L, M, Q, H
    box_size: int = 10
    border: int = 4
    fill_color: str = "black"
    back_color: str = "white"


_ERROR_CORRECTION_MAP: dict[str, int] = {
    "L": qrcode.constants.ERROR_CORRECT_L,
    "M": qrcode.constants.ERROR_CORRECT_M,
    "Q": qrcode.constants.ERROR_CORRECT_Q,
    "H": qrcode.constants.ERROR_CORRECT_H,
}


def _get_error_correction(level: str) -> int:
    level = (level or "H").upper().strip()
    if level not in _ERROR_CORRECTION_MAP:
        raise ValueError("error_correction must be one of: L, M, Q, H")
    return _ERROR_CORRECTION_MAP[level]


def _select_image_factory(output_path: str | os.PathLike[str]) -> Any | None:
    suffix = Path(output_path).suffix.lower()
    if suffix == ".svg":
        from qrcode.image.svg import SvgImage

        return SvgImage

    return None


def _ensure_parent_dir(path: str | os.PathLike[str]) -> None:
    parent = Path(path).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)


def generate_qr_image(data: str, config: QRConfig, *, output_path: str | None = None):
    validate_payload(data)

    image_factory = None
    if output_path is not None:
        image_factory = _select_image_factory(output_path)

    qr = qrcode.QRCode(
        version=config.version,
        error_correction=_get_error_correction(config.error_correction),
        box_size=config.box_size,
        border=config.border,
    )
    qr.add_data(data)
    qr.make(fit=config.version is None)

    img = qr.make_image(
        fill_color=config.fill_color,
        back_color=config.back_color,
        image_factory=image_factory,
    )

    return qr, img


def add_logo(img, logo_path: str, *, size_ratio: float = 0.2):
    from PIL import Image

    if not (0 < size_ratio <= 0.5):
        raise ValueError("size_ratio must be between 0 and 0.5")

    base = img.convert("RGBA")
    logo = Image.open(logo_path).convert("RGBA")

    width, height = base.size
    target = int(min(width, height) * size_ratio)

    resampling = getattr(Image, "Resampling", Image).LANCZOS
    logo.thumbnail((target, target), resampling)

    pad = max(2, int(target * 0.08))
    bg = Image.new("RGBA", (logo.width + pad * 2, logo.height + pad * 2), (255, 255, 255, 255))

    bg_pos = ((width - bg.width) // 2, (height - bg.height) // 2)
    logo_pos = ((width - logo.width) // 2, (height - logo.height) // 2)

    base.alpha_composite(bg, bg_pos)
    base.alpha_composite(logo, logo_pos)

    return base


def generate_qr(
    data: str,
    filename: str = "output_qr.png",
    *,
    config: QRConfig | None = None,
    logo_path: str | None = None,
    logo_size_ratio: float = 0.2,
) -> str:
    config = config or QRConfig()

    _, img = generate_qr_image(data, config, output_path=filename)

    if logo_path is not None:
        if Path(filename).suffix.lower() == ".svg":
            raise ValueError("Logo embedding is only supported for raster outputs (e.g. PNG)")

        img = add_logo(img, logo_path, size_ratio=logo_size_ratio)

    _ensure_parent_dir(filename)
    img.save(filename)
    return filename


def qr_to_ascii(data: str, *, config: QRConfig | None = None, invert: bool = False) -> str:
    config = config or QRConfig()
    qr, _ = generate_qr_image(data, config)

    matrix = qr.get_matrix()
    black, white = ("  ", "██") if invert else ("██", "  ")

    lines: list[str] = []
    for row in matrix:
        lines.append("".join(black if cell else white for cell in row))

    return "\n".join(lines)
