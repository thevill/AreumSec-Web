# AreumSec — Real-Time Threat Intelligence & Analysis

**AreumSec** is a real-time web-based cybersecurity threat analysis application built with Python Flask and Bootstrap. Designed for security analysts and VAPT professionals, it offers a clean, intelligence-agency-inspired interface for rapid file, URL, and IP/hash investigations.


### **Demo:**
![AreumSec_GIF_1](https://github.com/user-attachments/assets/78164df2-74e2-4e0e-9e0b-0a3891c84df5)
![AreumSec_GIF_2](https://github.com/user-attachments/assets/ae28f3d6-e14b-4f6b-9264-e36c9242a9d8)


### **Running the App:**<br>
```bash
pip install -r requirements.txt
```
```bash
python app.py
```


### **Features:**
1) Real-Time Analysis<br>
   URLs & Domains, IPv4 / IPv6 addresses, File Hash (SHA256), EML / MSG / TXT files
3) VirusTotal + Google SafeBrowsing Integration<br>
   API keys are securely managed in a separate config file.
5) DNSBL Check & Logging<br>
   All DNS Blacklist results are stored in a separate SQLite database.
6) Offline First<br>
   Lightweight and self-hosted — ideal for closed environments or air-gapped labs.


### **Tech Stack:**
1) Python 3
2) Flask (Backend)
3) Bootstrap 5 (Frontend)
4) SQLite (Separate DB for DNSBL results)
5) VirusTotal & Google SafeBrowsing APIs


### **API Keys:**<br>
Add your api_keys in config.py:<br>
