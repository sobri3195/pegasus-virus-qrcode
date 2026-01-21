# Ethical QR Code Generator

This project demonstrates how to generate QR codes using Python, specifically focusing on ethical security testing and the prevention of malicious requests.

## Features
- **Ethical Malware Simulation**: Uses the [EICAR Standard Antivirus Test String](https://en.wikipedia.org/wiki/EICAR_test_file) to simulate a "malicious" payload that is safe for systems but detectable by antivirus software.
- **Security Validation**: Implements a `reject-malicious-request` mechanism to identify and block common exploit patterns (like XSS or script injection).
- **Customizable QR Generation**: Uses the `qrcode` library for high-quality image generation.

## Installation
Ensure you have Python installed, then install the dependencies:
```bash
pip install -r requirements.txt
```

## Usage
Run the main script to see examples of safe, ethical-test, and rejected malicious payloads:
```bash
python main.py
```

## Disclaimer
This project is for educational and ethical security testing purposes only. Never use these tools to perform unauthorized actions on systems you do not own or have explicit permission to test.
