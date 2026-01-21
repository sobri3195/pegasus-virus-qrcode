import qrcode
import re
import os

# EICAR Standard Antivirus Test String
# This is a safe string used for testing antivirus software.
# It is NOT a real virus, but it is detected as one by security products.
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def is_malicious_request(data):
    """
    Validation logic to reject truly malicious or exploitative content.
    In a real-world scenario, this helps prevent attacks like XSS or command injection.
    """
    # Patterns common in malicious QR code payloads
    malicious_patterns = [
        r"javascript:",
        r"data:text/html",
        r"<script",
        r"cmd\.exe",
        r"/etc/passwd"
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

def generate_qr(data, filename="output_qr.png"):
    """
    Generates a QR code image from the provided data if it passes security checks.
    """
    print(f"Generating QR Code for data: {data[:50]}...")
    
    if is_malicious_request(data):
        print("ERROR: Malicious content detected. Request rejected for security reasons.")
        return False

    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filename), exist_ok=True) if os.path.dirname(filename) else None
        
        img.save(filename)
        print(f"SUCCESS: QR Code saved to {filename}")
        return True
    except Exception as e:
        print(f"FAILED: An error occurred: {e}")
        return False

if __name__ == "__main__":
    # Example 1: Ethical malware test (EICAR)
    print("\n--- Scenario 1: Generating Ethical Test QR (EICAR) ---")
    generate_qr(EICAR_STRING, "eicar_test.png")
    
    # Example 2: Normal safe URL
    print("\n--- Scenario 2: Generating Safe URL QR ---")
    generate_qr("https://sentry.io", "safe_url.png")
    
    # Example 3: Rejection of malicious payload
    print("\n--- Scenario 3: Rejecting Malicious Payload ---")
    generate_qr("javascript:alert('Exploit!')", "should_fail.png")
