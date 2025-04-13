#AreumSec — Real-Time Threat Intelligence & Analysis

AreumSec (아름 — Korean for graceful, beautiful) is a real-time web-based cybersecurity threat analysis application built with Python Flask and Bootstrap (Cyborg dark theme). Designed for security analysts and VAPT professionals, it offers a clean, intelligence-agency-inspired interface for rapid file, URL, and IP/hash investigations.


Demo:
![AreumSec_GIF_1](https://github.com/user-attachments/assets/78164df2-74e2-4e0e-9e0b-0a3891c84df5)
![AreumSec_GIF_2](https://github.com/user-attachments/assets/ae28f3d6-e14b-4f6b-9264-e36c9242a9d8)



Features:
1) Real-Time Analysis of:
     URLs & Domains
     IPv4 / IPv6 addresses
     File Hashes (MD5, SHA1, SHA256)
     EML / MSG / TXT files
2) VirusTotal + Google SafeBrowsing Integration
     API keys are securely managed in a separate config file.
4) DNSBL Check & Logging
     All DNS Blacklist results are stored in a separate SQLite database.
5) Offline First
     Lightweight and self-hosted — ideal for closed environments or air-gapped labs.


Tech Stack:
1) Python 3
2) Flask (Backend)
3) Bootstrap 5 (Frontend)
4) SQLite (Separate DB for DNSBL results)
5) VirusTotal & Google SafeBrowsing APIs


API Keys:
Add your api_keys in config.py:
{
  "virustotal": "YOUR_VT_KEY_HERE",
  "safebrowsing": "YOUR_SAFE_BROWSING_KEY_HERE"
}


Running the App:
pip install -r requirements.txt
python app.py


Screenshot
![image](https://github.com/user-attachments/assets/9b832343-a945-490d-bce4-4ea2194e57bb)
