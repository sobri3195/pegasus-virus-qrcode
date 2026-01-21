import argparse
import sys

from virs_qr.generator import QRConfig, generate_qr, qr_to_ascii
from virs_qr.templates import EICAR_STRING, build_payload, list_templates


def _parse_params(items: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid --param '{item}'. Use key=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --param '{item}'. Key cannot be empty")
        params[key] = value
    return params


def _config_from_args(args: argparse.Namespace) -> QRConfig:
    return QRConfig(
        version=args.version,
        error_correction=args.error_correction,
        box_size=args.box_size,
        border=args.border,
        fill_color=args.fill_color,
        back_color=args.back_color,
    )


def _resolve_payload(args: argparse.Namespace) -> str:
    if args.data is not None:
        return args.data

    if args.template is not None:
        params = _parse_params(args.param or [])
        return build_payload(args.template, params)

    raise ValueError("Either --data or --template is required")


def _cmd_list_templates(_args: argparse.Namespace) -> int:
    for t in list_templates():
        required = ", ".join(t.required_params) if t.required_params else "-"
        optional = ", ".join(t.optional_params) if t.optional_params else "-"
        print(f"{t.key}\n  {t.description}\n  required: {required}\n  optional: {optional}\n")
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    payload = _resolve_payload(args)
    config = _config_from_args(args)

    try:
        out = generate_qr(
            payload,
            args.output,
            config=config,
            logo_path=args.logo,
            logo_size_ratio=args.logo_size_ratio,
        )
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"SUCCESS: QR Code saved to {out}")

    if args.print_ascii:
        print(qr_to_ascii(payload, config=config, invert=args.invert))

    return 0


def _cmd_ascii(args: argparse.Namespace) -> int:
    payload = _resolve_payload(args)
    config = _config_from_args(args)

    try:
        print(qr_to_ascii(payload, config=config, invert=args.invert))
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    return 0


def _demo() -> None:
    print("\n--- Demo 1: Generating Ethical Test QR (EICAR) ---")
    generate_qr(EICAR_STRING, "eicar_test.png")

    print("\n--- Demo 2: Generating Safe URL QR ---")
    generate_qr("https://sentry.io", "safe_url.png")

    print("\n--- Demo 3: Rejecting Malicious Payload ---")
    try:
        generate_qr("javascript:alert('Exploit!')", "should_fail.png")
    except Exception as e:
        print(f"EXPECTED FAILURE: {e}")

    print("\n--- Demo 4: Listing 50 built-in templates ---")
    print(f"Total templates: {len(list_templates())}")
    print("Try: python main.py list-templates")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="virs-qr",
        description="QR code generator with security validation and 50 payload templates.",
    )

    sub = parser.add_subparsers(dest="command")

    list_p = sub.add_parser("list-templates", help="List available payload templates")
    list_p.set_defaults(func=_cmd_list_templates)

    def add_payload_args(p: argparse.ArgumentParser) -> None:
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--data", help="Raw payload data")
        g.add_argument("--template", help="Template key (see list-templates)")
        p.add_argument(
            "--param",
            action="append",
            default=[],
            help="Template parameter in key=value form (repeatable)",
        )

    def add_qr_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--output", default="output_qr.png", help="Output path (.png or .svg)")
        p.add_argument("--error-correction", default="H", help="L, M, Q, or H")
        p.add_argument("--box-size", type=int, default=10)
        p.add_argument("--border", type=int, default=4)
        p.add_argument("--fill-color", default="black")
        p.add_argument("--back-color", default="white")
        p.add_argument("--version", type=int, default=None, help="QR version (1-40); omit for auto")

    gen = sub.add_parser("generate", help="Generate a QR image")
    add_payload_args(gen)
    add_qr_args(gen)
    gen.add_argument("--logo", help="Path to a logo image to embed (PNG/JPG)")
    gen.add_argument("--logo-size-ratio", type=float, default=0.2)
    gen.add_argument("--print-ascii", action="store_true", help="Also print ASCII QR to stdout")
    gen.add_argument("--invert", action="store_true", help="Invert ASCII colors")
    gen.set_defaults(func=_cmd_generate)

    ascii_p = sub.add_parser("ascii", help="Print an ASCII QR to stdout")
    add_payload_args(ascii_p)
    add_qr_args(ascii_p)
    ascii_p.add_argument("--invert", action="store_true", help="Invert ASCII colors")
    ascii_p.set_defaults(func=_cmd_ascii)

    args = parser.parse_args(argv)

    if not args.command:
        _demo()
        return 0

    try:
        return args.func(args)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
