# AreumSec — Real-Time Threat Intelligence & Analysis

**AreumSec** is a real-time web-based cybersecurity threat analysis application built with Python Flask and Bootstrap. Designed for security analysts and VAPT professionals, it offers a clean, intelligence-agency-inspired interface for rapid file, URL, and IP/hash investigations.


### **Command-Line version:**
https://github.com/thevill/AreumSec-CLI


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
   A separate list of DNS Blacklist.
6) Offline First<br>
   Lightweight and self-hosted — ideal for closed environments or air-gapped labs.


### **Tech Stack:**
1) Python 3
2) Flask (Backend)
3) Bootstrap 5 (Frontend)
4) SQLite
5) VirusTotal & Google SafeBrowsing APIs


### **API Keys:**<br>
Add your API keys in config<br>

<br>
<a href="https://razorpay.me/@areumsec" target="_blank" style="text-decoration: none;">
  <button style="display: flex; align-items: center; gap: 10px; background:#0f9d58; color:white; padding:10px 20px; border:none; border-radius:5px; cursor: pointer;">
    <img src="https://cdn.razorpay.com/logo.svg" alt="Razorpay" style="height: 20px;">
    Donate via UPI (Razorpay)
  </button>
</a>

