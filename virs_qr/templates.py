from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import quote, urlencode, urlparse, urlunparse

# EICAR Standard Antivirus Test String (safe for demos)
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@dataclass(frozen=True, slots=True)
class Template:
    key: str
    description: str
    required_params: tuple[str, ...]
    optional_params: tuple[str, ...]
    builder: Callable[[Mapping[str, str]], str]


def _require(params: Mapping[str, str], key: str) -> str:
    if key not in params or params[key] == "":
        raise ValueError(f"Missing required param: {key}")
    return params[key]


def _optional(params: Mapping[str, str], key: str, default: str = "") -> str:
    return params.get(key, default)


def _ensure_scheme(url: str, scheme: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = parsed._replace(scheme=scheme)
    if parsed.scheme.lower() != scheme.lower():
        parsed = parsed._replace(scheme=scheme)
    return urlunparse(parsed)


def _build_mailto(params: Mapping[str, str]) -> str:
    to = _require(params, "to")
    subject = _optional(params, "subject")
    body = _optional(params, "body")

    query: dict[str, str] = {}
    if subject:
        query["subject"] = subject
    if body:
        query["body"] = body

    return f"mailto:{to}" + (f"?{urlencode(query)}" if query else "")


def _build_matmsg(params: Mapping[str, str]) -> str:
    to = _require(params, "to")
    subject = _optional(params, "subject")
    body = _optional(params, "body")

    # MATMSG is a common QR email format supported by many scanners
    return f"MATMSG:TO:{to};SUB:{subject};BODY:{body};;"


def _build_sms(params: Mapping[str, str]) -> str:
    number = _require(params, "number")
    message = _optional(params, "message")

    if message:
        return f"SMSTO:{number}:{message}"
    return f"SMSTO:{number}:"


def _build_wifi(params: Mapping[str, str], auth: str) -> str:
    ssid = _require(params, "ssid")
    password = _optional(params, "password")
    hidden = _optional(params, "hidden", "false").lower() in {"1", "true", "yes"}

    # WIFI payload format
    # https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android
    pieces = [f"WIFI:T:{auth};", f"S:{ssid};"]
    if auth != "nopass":
        pieces.append(f"P:{password};")
    if hidden:
        pieces.append("H:true;")
    pieces.append(";")
    return "".join(pieces)


def _build_vcard(params: Mapping[str, str]) -> str:
    name = _require(params, "name")
    phone = _optional(params, "phone")
    email = _optional(params, "email")
    org = _optional(params, "org")
    title = _optional(params, "title")
    url = _optional(params, "url")
    address = _optional(params, "address")
    note = _optional(params, "note")

    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"FN:{name}",
    ]

    if phone:
        lines.append(f"TEL;TYPE=CELL:{phone}")
    if email:
        lines.append(f"EMAIL:{email}")
    if org:
        lines.append(f"ORG:{org}")
    if title:
        lines.append(f"TITLE:{title}")
    if url:
        lines.append(f"URL:{url}")
    if address:
        lines.append(f"ADR:;;{address};;;;")
    if note:
        lines.append(f"NOTE:{note}")

    lines.append("END:VCARD")
    return "\n".join(lines)


def _build_mecard(params: Mapping[str, str]) -> str:
    name = _require(params, "name")
    phone = _optional(params, "phone")
    email = _optional(params, "email")
    url = _optional(params, "url")

    parts = [f"MECARD:N:{name};"]
    if phone:
        parts.append(f"TEL:{phone};")
    if email:
        parts.append(f"EMAIL:{email};")
    if url:
        parts.append(f"URL:{url};")
    parts.append(";")
    return "".join(parts)


def _build_geo(params: Mapping[str, str]) -> str:
    lat = _require(params, "lat")
    lon = _require(params, "lon")
    query = _optional(params, "query")

    payload = f"geo:{lat},{lon}"
    if query:
        payload += f"?q={quote(query)}"
    return payload


def _build_google_maps(params: Mapping[str, str]) -> str:
    lat = _require(params, "lat")
    lon = _require(params, "lon")
    return f"https://www.google.com/maps?q={quote(lat)},{quote(lon)}"


def _build_ics_event(params: Mapping[str, str]) -> str:
    summary = _require(params, "summary")
    dtstart = _require(params, "dtstart")  # e.g. 20260121T120000Z
    dtend = _optional(params, "dtend")
    location = _optional(params, "location")
    description = _optional(params, "description")

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "BEGIN:VEVENT",
        f"SUMMARY:{summary}",
        f"DTSTART:{dtstart}",
    ]

    if dtend:
        lines.append(f"DTEND:{dtend}")
    if location:
        lines.append(f"LOCATION:{location}")
    if description:
        lines.append(f"DESCRIPTION:{description}")

    lines.extend(["END:VEVENT", "END:VCALENDAR"])
    return "\n".join(lines)


def _build_google_calendar_link(params: Mapping[str, str]) -> str:
    text = _require(params, "text")
    start = _require(params, "start")  # 20260121T120000Z
    end = _require(params, "end")
    details = _optional(params, "details")
    location = _optional(params, "location")

    query: dict[str, str] = {
        "action": "TEMPLATE",
        "text": text,
        "dates": f"{start}/{end}",
    }
    if details:
        query["details"] = details
    if location:
        query["location"] = location

    return "https://calendar.google.com/calendar/render?" + urlencode(query)


def _build_crypto_uri(params: Mapping[str, str], scheme: str) -> str:
    address = _require(params, "address")

    query: dict[str, str] = {}
    amount = _optional(params, "amount")
    label = _optional(params, "label")
    message = _optional(params, "message")

    if amount:
        query["amount"] = amount
    if label:
        query["label"] = label
    if message:
        query["message"] = message

    return f"{scheme}:{address}" + (f"?{urlencode(query)}" if query else "")


def _build_paypal_me(params: Mapping[str, str]) -> str:
    username = _require(params, "username")
    amount = _optional(params, "amount")

    url = f"https://paypal.me/{quote(username)}"
    if amount:
        url += f"/{quote(amount)}"
    return url


def _build_upi(params: Mapping[str, str]) -> str:
    pa = _require(params, "pa")  # VPA
    pn = _require(params, "pn")  # Payee name
    am = _optional(params, "am")
    tn = _optional(params, "tn")
    cu = _optional(params, "cu", "INR")

    query: dict[str, str] = {"pa": pa, "pn": pn, "cu": cu}
    if am:
        query["am"] = am
    if tn:
        query["tn"] = tn

    return "upi://pay?" + urlencode(query)


def _build_sepa(params: Mapping[str, str]) -> str:
    # EPC QR Code for SEPA Credit Transfer (SCT) - simplified
    name = _require(params, "name")
    iban = _require(params, "iban")
    bic = _require(params, "bic")
    amount = _require(params, "amount")  # EUR amount without currency, e.g. 12.34

    purpose = _optional(params, "purpose")
    remittance = _optional(params, "remittance")
    information = _optional(params, "information")

    lines = [
        "BCD",
        "001",
        "1",
        "SCT",
        bic,
        name,
        iban,
        f"EUR{amount}",
        purpose,
        remittance,
        information,
    ]

    return "\n".join(lines)


def _build_social_url(params: Mapping[str, str], base: str, key: str = "handle") -> str:
    handle = _require(params, key)
    return base.rstrip("/") + "/" + quote(handle.lstrip("@"))


def _build_discord_invite(params: Mapping[str, str]) -> str:
    invite = _require(params, "invite")
    return "https://discord.gg/" + quote(invite)


def _build_slack_channel(params: Mapping[str, str]) -> str:
    channel = _require(params, "channel")
    team = _optional(params, "team")

    query: dict[str, str] = {"channel": channel}
    if team:
        query["team"] = team
    return "https://slack.com/app_redirect?" + urlencode(query)


def _build_zoom(params: Mapping[str, str]) -> str:
    meeting_id = _require(params, "meeting_id")
    pwd = _optional(params, "pwd")

    url = f"https://zoom.us/j/{quote(meeting_id)}"
    if pwd:
        url += f"?pwd={quote(pwd)}"
    return url


def _build_spotify_track(params: Mapping[str, str]) -> str:
    track_id = _require(params, "track_id")
    return f"https://open.spotify.com/track/{quote(track_id)}"


def _build_appstore(params: Mapping[str, str]) -> str:
    app_id = _require(params, "app_id")
    app_id = app_id.lower().removeprefix("id")
    return f"https://apps.apple.com/app/id{quote(app_id)}"


def _build_googleplay(params: Mapping[str, str]) -> str:
    package = _require(params, "package")
    return "https://play.google.com/store/apps/details?id=" + quote(package)


def _build_deeplink(params: Mapping[str, str]) -> str:
    scheme = _require(params, "scheme")
    path = _require(params, "path")
    query = _optional(params, "query")

    url = f"{scheme}://{path.lstrip('/')}"
    if query:
        url += "?" + query.lstrip("?")
    return url


def _build_json(params: Mapping[str, str]) -> str:
    raw = _require(params, "json")
    obj = json.loads(raw)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _build_csv_row(params: Mapping[str, str]) -> str:
    values = _require(params, "values")
    return values


def _build_markdown_link(params: Mapping[str, str]) -> str:
    text = _require(params, "text")
    url = _require(params, "url")
    return f"[{text}]({url})"


def _build_otpauth_totp(params: Mapping[str, str]) -> str:
    label = _require(params, "label")
    secret = _require(params, "secret")
    issuer = _optional(params, "issuer")
    digits = _optional(params, "digits", "6")
    period = _optional(params, "period", "30")

    query: dict[str, str] = {"secret": secret, "digits": digits, "period": period}
    if issuer:
        query["issuer"] = issuer

    return f"otpauth://totp/{quote(label)}?{urlencode(query)}"


def _build_otpauth_hotp(params: Mapping[str, str]) -> str:
    label = _require(params, "label")
    secret = _require(params, "secret")
    counter = _require(params, "counter")
    issuer = _optional(params, "issuer")
    digits = _optional(params, "digits", "6")

    query: dict[str, str] = {"secret": secret, "counter": counter, "digits": digits}
    if issuer:
        query["issuer"] = issuer

    return f"otpauth://hotp/{quote(label)}?{urlencode(query)}"


def _build_custom_prefix(params: Mapping[str, str]) -> str:
    prefix = _require(params, "prefix")
    value = _require(params, "value")
    return f"{prefix}{value}"


TEMPLATES: dict[str, Template] = {
    # Text
    "text": Template(
        key="text",
        description="Plain text",
        required_params=("text",),
        optional_params=(),
        builder=lambda p: _require(p, "text"),
    ),
    "text-uppercase": Template(
        key="text-uppercase",
        description="Plain text uppercased",
        required_params=("text",),
        optional_params=(),
        builder=lambda p: _require(p, "text").upper(),
    ),
    "text-lowercase": Template(
        key="text-lowercase",
        description="Plain text lowercased",
        required_params=("text",),
        optional_params=(),
        builder=lambda p: _require(p, "text").lower(),
    ),
    # URLs
    "url": Template(
        key="url",
        description="URL (as provided)",
        required_params=("url",),
        optional_params=(),
        builder=lambda p: _require(p, "url"),
    ),
    "url-https": Template(
        key="url-https",
        description="Force HTTPS scheme",
        required_params=("url",),
        optional_params=(),
        builder=lambda p: _ensure_scheme(_require(p, "url"), "https"),
    ),
    "url-http": Template(
        key="url-http",
        description="Force HTTP scheme",
        required_params=("url",),
        optional_params=(),
        builder=lambda p: _ensure_scheme(_require(p, "url"), "http"),
    ),
    "url-utm": Template(
        key="url-utm",
        description="URL with UTM parameters",
        required_params=("base_url", "utm_source", "utm_medium"),
        optional_params=("utm_campaign", "utm_term", "utm_content"),
        builder=lambda p: _ensure_scheme(
            _require(p, "base_url"), "https"
        )
        + "?"
        + urlencode(
            {
                "utm_source": _require(p, "utm_source"),
                "utm_medium": _require(p, "utm_medium"),
                **({"utm_campaign": p["utm_campaign"]} if p.get("utm_campaign") else {}),
                **({"utm_term": p["utm_term"]} if p.get("utm_term") else {}),
                **({"utm_content": p["utm_content"]} if p.get("utm_content") else {}),
            }
        ),
    ),
    # Contact
    "email-mailto": Template(
        key="email-mailto",
        description="Email using mailto:",
        required_params=("to",),
        optional_params=("subject", "body"),
        builder=_build_mailto,
    ),
    "email-simple": Template(
        key="email-simple",
        description="Email using MATMSG format",
        required_params=("to",),
        optional_params=("subject", "body"),
        builder=_build_matmsg,
    ),
    "phone": Template(
        key="phone",
        description="Telephone number (tel:)",
        required_params=("number",),
        optional_params=(),
        builder=lambda p: "tel:" + _require(p, "number"),
    ),
    "sms": Template(
        key="sms",
        description="SMS (SMSTO)",
        required_params=("number",),
        optional_params=("message",),
        builder=_build_sms,
    ),
    "whatsapp": Template(
        key="whatsapp",
        description="WhatsApp wa.me link",
        required_params=("phone",),
        optional_params=("text",),
        builder=lambda p: "https://wa.me/"
        + quote(_require(p, "phone").lstrip("+"))
        + ("?" + urlencode({"text": p["text"]}) if p.get("text") else ""),
    ),
    "telegram": Template(
        key="telegram",
        description="Telegram username link",
        required_params=("username",),
        optional_params=(),
        builder=lambda p: "https://t.me/" + quote(_require(p, "username").lstrip("@")),
    ),
    # Location
    "geo": Template(
        key="geo",
        description="Geo coordinates (geo: URI)",
        required_params=("lat", "lon"),
        optional_params=("query",),
        builder=_build_geo,
    ),
    "google-maps": Template(
        key="google-maps",
        description="Google Maps query link",
        required_params=("lat", "lon"),
        optional_params=(),
        builder=_build_google_maps,
    ),
    # WiFi
    "wifi-wpa": Template(
        key="wifi-wpa",
        description="WiFi config (WPA)",
        required_params=("ssid", "password"),
        optional_params=("hidden",),
        builder=lambda p: _build_wifi(p, "WPA"),
    ),
    "wifi-wpa2": Template(
        key="wifi-wpa2",
        description="WiFi config (WPA2)",
        required_params=("ssid", "password"),
        optional_params=("hidden",),
        builder=lambda p: _build_wifi(p, "WPA2"),
    ),
    "wifi-wep": Template(
        key="wifi-wep",
        description="WiFi config (WEP)",
        required_params=("ssid", "password"),
        optional_params=("hidden",),
        builder=lambda p: _build_wifi(p, "WEP"),
    ),
    "wifi-nopass": Template(
        key="wifi-nopass",
        description="WiFi config (open network)",
        required_params=("ssid",),
        optional_params=("hidden",),
        builder=lambda p: _build_wifi(p, "nopass"),
    ),
    # Business cards
    "vcard": Template(
        key="vcard",
        description="vCard (VCF) contact",
        required_params=("name",),
        optional_params=("phone", "email", "org", "title", "url", "address", "note"),
        builder=_build_vcard,
    ),
    "mecard": Template(
        key="mecard",
        description="MeCard contact",
        required_params=("name",),
        optional_params=("phone", "email", "url"),
        builder=_build_mecard,
    ),
    # Events
    "event-ics": Template(
        key="event-ics",
        description="iCalendar VEVENT",
        required_params=("summary", "dtstart"),
        optional_params=("dtend", "location", "description"),
        builder=_build_ics_event,
    ),
    "event-google-calendar": Template(
        key="event-google-calendar",
        description="Google Calendar template link",
        required_params=("text", "start", "end"),
        optional_params=("details", "location"),
        builder=_build_google_calendar_link,
    ),
    # Payments
    "bitcoin": Template(
        key="bitcoin",
        description="Bitcoin URI",
        required_params=("address",),
        optional_params=("amount", "label", "message"),
        builder=lambda p: _build_crypto_uri(p, "bitcoin"),
    ),
    "ethereum": Template(
        key="ethereum",
        description="Ethereum URI",
        required_params=("address",),
        optional_params=("amount", "label", "message"),
        builder=lambda p: _build_crypto_uri(p, "ethereum"),
    ),
    "litecoin": Template(
        key="litecoin",
        description="Litecoin URI",
        required_params=("address",),
        optional_params=("amount", "label", "message"),
        builder=lambda p: _build_crypto_uri(p, "litecoin"),
    ),
    "paypal-me": Template(
        key="paypal-me",
        description="PayPal.me link",
        required_params=("username",),
        optional_params=("amount",),
        builder=_build_paypal_me,
    ),
    "upi": Template(
        key="upi",
        description="UPI payment URI",
        required_params=("pa", "pn"),
        optional_params=("am", "tn", "cu"),
        builder=_build_upi,
    ),
    "sepa-credit-transfer": Template(
        key="sepa-credit-transfer",
        description="EPC SEPA Credit Transfer payload",
        required_params=("name", "iban", "bic", "amount"),
        optional_params=("purpose", "remittance", "information"),
        builder=_build_sepa,
    ),
    # Social
    "linkedin": Template(
        key="linkedin",
        description="LinkedIn profile",
        required_params=("handle",),
        optional_params=(),
        builder=lambda p: _build_social_url(p, "https://www.linkedin.com/in"),
    ),
    "github": Template(
        key="github",
        description="GitHub profile",
        required_params=("handle",),
        optional_params=(),
        builder=lambda p: _build_social_url(p, "https://github.com"),
    ),
    "twitter": Template(
        key="twitter",
        description="X/Twitter profile",
        required_params=("handle",),
        optional_params=(),
        builder=lambda p: _build_social_url(p, "https://twitter.com"),
    ),
    "facebook": Template(
        key="facebook",
        description="Facebook profile",
        required_params=("handle",),
        optional_params=(),
        builder=lambda p: _build_social_url(p, "https://facebook.com"),
    ),
    "instagram": Template(
        key="instagram",
        description="Instagram profile",
        required_params=("handle",),
        optional_params=(),
        builder=lambda p: _build_social_url(p, "https://instagram.com"),
    ),
    "youtube": Template(
        key="youtube",
        description="YouTube handle",
        required_params=("handle",),
        optional_params=(),
        builder=lambda p: "https://youtube.com/@" + quote(_require(p, "handle").lstrip("@")),
    ),
    # Chat/Community
    "discord": Template(
        key="discord",
        description="Discord invite",
        required_params=("invite",),
        optional_params=(),
        builder=_build_discord_invite,
    ),
    "slack": Template(
        key="slack",
        description="Slack channel redirect",
        required_params=("channel",),
        optional_params=("team",),
        builder=_build_slack_channel,
    ),
    # Meetings & Media
    "zoom-meeting": Template(
        key="zoom-meeting",
        description="Zoom meeting link",
        required_params=("meeting_id",),
        optional_params=("pwd",),
        builder=_build_zoom,
    ),
    "spotify-track": Template(
        key="spotify-track",
        description="Spotify track link",
        required_params=("track_id",),
        optional_params=(),
        builder=_build_spotify_track,
    ),
    # App stores
    "appstore": Template(
        key="appstore",
        description="Apple App Store link",
        required_params=("app_id",),
        optional_params=(),
        builder=_build_appstore,
    ),
    "googleplay": Template(
        key="googleplay",
        description="Google Play Store link",
        required_params=("package",),
        optional_params=(),
        builder=_build_googleplay,
    ),
    # Deep links
    "app-deeplink": Template(
        key="app-deeplink",
        description="Custom app deep link",
        required_params=("scheme", "path"),
        optional_params=("query",),
        builder=_build_deeplink,
    ),
    # Structured data
    "json": Template(
        key="json",
        description="Minified JSON (validated)",
        required_params=("json",),
        optional_params=(),
        builder=_build_json,
    ),
    "csv-row": Template(
        key="csv-row",
        description="CSV row as provided",
        required_params=("values",),
        optional_params=(),
        builder=_build_csv_row,
    ),
    "markdown-link": Template(
        key="markdown-link",
        description="Markdown link",
        required_params=("text", "url"),
        optional_params=(),
        builder=_build_markdown_link,
    ),
    # OTP
    "otp-totp": Template(
        key="otp-totp",
        description="TOTP otpauth:// URI",
        required_params=("label", "secret"),
        optional_params=("issuer", "digits", "period"),
        builder=_build_otpauth_totp,
    ),
    "otp-hotp": Template(
        key="otp-hotp",
        description="HOTP otpauth:// URI",
        required_params=("label", "secret", "counter"),
        optional_params=("issuer", "digits"),
        builder=_build_otpauth_hotp,
    ),
    # Ethical demos
    "eicar-test": Template(
        key="eicar-test",
        description="EICAR standard test string (safe antivirus demo)",
        required_params=(),
        optional_params=(),
        builder=lambda _p: EICAR_STRING,
    ),
    "safe-demo-sentry": Template(
        key="safe-demo-sentry",
        description="Safe demo URL (sentry.io)",
        required_params=(),
        optional_params=(),
        builder=lambda _p: "https://sentry.io",
    ),
    # Utility
    "custom-prefix": Template(
        key="custom-prefix",
        description="Prefix + value",
        required_params=("prefix", "value"),
        optional_params=(),
        builder=_build_custom_prefix,
    ),
}


def build_payload(template_key: str, params: Mapping[str, str]) -> str:
    if template_key not in TEMPLATES:
        raise KeyError(f"Unknown template: {template_key}")

    template = TEMPLATES[template_key]
    missing = [k for k in template.required_params if k not in params or params[k] == ""]
    if missing:
        raise ValueError(f"Missing required params for {template_key}: {', '.join(missing)}")

    return template.builder(params)


def list_templates() -> list[Template]:
    return [TEMPLATES[k] for k in sorted(TEMPLATES.keys())]
