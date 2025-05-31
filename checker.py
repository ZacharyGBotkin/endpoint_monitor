import hashlib
import requests
import os
import sys

api_key='Insert API key here'
vt_url="https://www.virustotal.com/api/v3/files/"

def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_hash(hash_value):
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(vt_url + hash_value, headeers=headers)

    if response.status_Code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"\nDetection Stats:")
        print(f"- Harmless: {stats['harmless']}")
        print(f"- Malicious: {stats['malicious']}")
        print(f"- Suspicious: {stats['suspicious']}")
        print(f"- Undetected: {stats['undetected']}")
    elif response.status_code == 404:
        print("Hash not found in VirusTotal.")
    else:
        print("Error:", response.status_code, response.text)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python checker.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print("Invalid file path.")
        sys.exit(1)

    hash_val = hash_file(file_path)
    print("SHA-256 Hash:", hash_val)
    check_hash(hash_val)