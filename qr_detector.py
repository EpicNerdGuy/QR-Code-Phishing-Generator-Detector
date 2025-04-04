from pyzbar.pyzbar import decode
from PIL import  Image
import requests

def scan_qr_code(image_path):
    img = Image.open(image_path)
    decoded_objects = decode(img)
    if not decoded_objects:
        return "QR not detected"

    for obj in decoded_objects:
        payload = obj.data.decode("utf-8")
        print(f"Detected content : {payload}")
        # return analyze_payload(payload)