# Virs QR Code Generator

Generate QR codes using Python for educational and ethical security testing.

## Highlights

- **Security validation**: Blocks common exploit-like payloads (e.g. `javascript:` or HTML script tags) using `is_malicious_request` / `validate_payload`.
- **Ethical malware demo**: Includes the **EICAR Standard Antivirus Test String** (safe test payload) as a built-in template.
- **50 built-in payload templates**: WiFi, vCard, SMS, geo, OTP Auth, app store links, payment URIs, and more.
- **Customizable QR generation**: Configure error correction, colors, border, and box size.
- **Multiple outputs**: PNG (default) and SVG.
- **Optional logo embedding**: Embed a logo in the center of PNG output.
- **ASCII output**: Print a QR code in your terminal.

## Installation

Ensure you have Python installed, then install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Run the demo

```bash
python main.py
```

### List the 50 templates

```bash
python main.py list-templates
```

### Generate a QR code from a template

```bash
python main.py generate \
  --template wifi-wpa2 \
  --param ssid=MyWiFi \
  --param password=supersecret \
  --output out/wifi.png
```

### Generate a QR code from raw data

```bash
python main.py generate --data "https://sentry.io" --output out/sentry.svg
```

### Print an ASCII QR code

```bash
python main.py ascii --template eicar-test
```

## Author

**Lettu Kes dr. Muhammad Sobri Maulana, S.Kom, CEH, OSCP, OSCE**

## Contact & Social Media

- **Email**: muhammadsobrimaulana31@gmail.com
- **GitHub**: https://github.com/sobri3195
- **Website**: https://muhammadsobrimaulana.netlify.app

### Social Media

- **YouTube**: https://www.youtube.com/@muhammadsobrimaulana6013
- **Telegram**: https://t.me/winlin_exploit
- **TikTok**: https://www.tiktok.com/@dr.sobri
- **WhatsApp Group**: https://chat.whatsapp.com/B8nwRZOBMo64GjTwdXV8Bl

### Support & Donation

- **Trakteer**: https://trakteer.id/g9mkave5gauns962u07t
- **Lynk.id**: https://lynk.id/muhsobrimaulana
- **Gumroad**: https://maulanasobri.gumroad.com/
- **Karyakarsa**: https://karyakarsa.com/muhammadsobrimaulana
- **Nyawer**: https://nyawer.co/MuhammadSobriMaulana
- **Sevalla**: https://muhammad-sobri-maulana-kvr6a.sevalla.page/

### Online Store

- **Toko Online Sobri**: https://pegasus-shop.netlify.app

## Disclaimer

This project is for educational and ethical security testing purposes only. Never use these tools to perform unauthorized actions on systems you do not own or have explicit permission to test.
