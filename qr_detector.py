import argparse
from pyzbar.pyzbar import decode
from PIL import Image
import requests
from urllib.parse import urlparse
import re
from dotenv import load_dotenv
import os


load_dotenv()
api_key = os.getenv("API_KEY")

def is_suspicious_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    suspicious_keywords = ["login", "secure", "verify", "update", "bank", "free", "gift", "account"]
    suspicious_domains = ["bit.ly", "tinyurl.com", "0x0.st", "grabify.link"]

    if any(short in domain for short in suspicious_domains):
        return True

    if any(keyword in url.lower() for keyword in suspicious_keywords):
        return True

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return True

    return False

def check_url_virustotal(url, api_key):
    headers = {
        "x-apikey": api_key
    }
    params = {
        "url": url
    }
    response = requests.post("https://www.virustotal.com/api/v3/urls", data=params, headers=headers)

    if response.status_code != 200:
        return f"Error while submitting to VirusTotal: {response.status_code}"

    analysis_url_id = response.json()["data"]["id"]
    analysis_result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_url_id}", headers=headers)

    if analysis_result.status_code != 200:
        return f"Error while retrieving analysis: {analysis_result.status_code}"

    stats = analysis_result.json()["data"]["attributes"]["stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]

    if malicious > 0 or suspicious > 0:
        return f"⚠️ Suspicious URL: {malicious} malicious, {suspicious} suspicious."
    else:
        return "✅ Safe according to VirusTotal."

def scan_qr_code(image_path, api_key):
    try:
        img = Image.open(image_path)
    except Exception as e:
        return f"Error opening image: {e}"

    decoded_objects = decode(img)
    if not decoded_objects:
        return "❌ QR code not detected."

    for obj in decoded_objects:
        payload = obj.data.decode("utf-8")
        print(f"🔍 Detected URL: {payload}")

        if is_suspicious_url(payload):
            print("⚠️ This URL looks suspicious (local check).")
        else:
            print("✅ No local signs of phishing.")

        vt_result = check_url_virustotal(payload, api_key)
        print(vt_result)

# CLI entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="QR Code Phishing Scanner - Detects and checks malicious QR links using VirusTotal."
    )
    parser.add_argument("image", help="Path to the image containing the QR code.")
    args = parser.parse_args()
