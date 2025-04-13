# app.py
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
from config import Config
from models import db, DNSBL
from utils.email_analyzer import (
    extract_sender_info, extract_sender_ip, extract_subject,
    extract_urls, extract_auth_data, calculate_sha256
)
from utils.threat_intel import (
    check_ip_dnsbl, check_organization, query_virustotal,
    query_virustotal_file, query_safe_browsing_url
)

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize database with DNSBLs
def init_db():
    with app.app_context():
        db.create_all()
        default_dnsbls = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
                          "xbl.spamhaus.org","z.mailspike.net","zen.spamhaus.org",
                          "zombie.dnsbl.sorbs.net","multi.surbl.org","dnsbl.invaluement.com",
                          "b.barracudacentral.org","bl.spamcop.net","blacklist.woody.ch",
                          "bogons.cymru.com","cbl.abuseat.org","combined.abuse.ch","db.wpbl.info",
                          "dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net",
                          "dnsbl.dronebl.org","dnsbl.sorbs.net","drone.abuse.ch","duinv.aupads.org",
                          "dul.dnsbl.sorbs.net","dyna.spamrats.com","http.dnsbl.sorbs.net",
                          "ips.backscatterer.org","ix.dnsbl.manitu.net","korea.services.net",
                          "misc.dnsbl.sorbs.net","noptr.spamrats.com","orvedb.aupads.org",
                          "pbl.spamhaus.org","proxy.bl.gweep.ca","psbl.surriel.com",
                          "relays.bl.gweep.ca","relays.nether.net","sbl.spamhaus.org",
                          "singular.ttk.pte.hu","smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net",
                          "spam.abuse.ch","spam.dnsbl.anonmails.de","spam.dnsbl.sorbs.net",
                          "spam.spamrats.com","spambot.bls.digibase.ca","spamrbl.imp.ch",
                          "spamsources.fabel.dk","ubl.lashback.com","ubl.unsubscore.com",
                          "virus.rbl.jp","web.dnsbl.sorbs.net","wormrbl.imp.ch"]
        for dnsbl in default_dnsbls:
            if not DNSBL.query.filter_by(name=dnsbl).first():
                db.session.add(DNSBL(name=dnsbl))
        db.session.commit()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    input_type = request.form.get('input_type')
    results = {}

    if input_type == 'file':
        if 'file' not in request.files:
            return render_template('error.html', message="No file uploaded")
        file = request.files['file']
        if file.filename == '':
            return render_template('error.html', message="No file selected")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            p1_sender, p2_sender, sender_domain = extract_sender_info(file_path)
            sender_ip = extract_sender_ip(file_path)
            subject = extract_subject(file_path)
            urls = extract_urls(file_path)
            auth_data = extract_auth_data(file_path)
            
            url_results = []
            for url in urls:
                vt_result = query_virustotal(url)
                gsb_result = query_safe_browsing_url(url)
                url_results.append({
                    "url": url,
                    "virustotal": vt_result,
                    "safebrowsing": gsb_result
                })
            
            sha256 = calculate_sha256(file_path)
            vt_file_result = query_virustotal_file(file_path, sha256) if sha256 else {"verdict": "Unable to calculate SHA256", "engines": [], "history": []}
            
            results = {
                "file": file_path,
                "p1_sender": p1_sender,
                "p2_sender": p2_sender,
                "sender_domain": sender_domain,
                "sender_ip": sender_ip or "Not found",
                "subject": subject,
                "auth_data": auth_data,
                "urls": url_results or "No URLs found",
                "organization": check_organization(sender_ip, sender_domain) if sender_ip else "No IP provided",
                "dnsbl": check_ip_dnsbl(sender_ip) if sender_ip else ["No IP provided"],
                "vt_file": vt_file_result,
                "verdict": "Suspicious" if (
                    any("Malicious" in ur["virustotal"]["verdict"] or "Malicious" in ur["safebrowsing"] for ur in url_results) or
                    vt_file_result["verdict"] == "Malicious" or
                    "listed in" in str(check_ip_dnsbl(sender_ip))
                ) else "Likely safe"
            }
            
            os.remove(file_path)  # Clean up uploaded file
            
    elif input_type == 'url':
        url = request.form.get('url')
        if not url:
            return render_template('error.html', message="No URL provided")
        vt_result = query_virustotal(url)
        gsb_result = query_safe_browsing_url(url)
        results = {
            "url": url,
            "virustotal": vt_result,
            "safebrowsing": gsb_result,
            "verdict": "Suspicious" if "Malicious" in vt_result["verdict"] or gsb_result == "Malicious" else "Likely safe"
        }
    
    elif input_type == 'ip':
        ip = request.form.get('ip')
        if not ip:
            return render_template('error.html', message="No IP provided")
        dnsbl_result = check_ip_dnsbl(ip)
        # Handle dnsbl_result as a list
        dnsbl_display = "Listed in " + ", ".join(dnsbl_result) if dnsbl_result and dnsbl_result != ["Not listed in any DNSBLs"] else "Not listed in any DNSBLs"
        results = {
            "ip": ip,
            "dnsbl": dnsbl_display,
            "verdict": "Suspicious" if dnsbl_result and dnsbl_result != ["Not listed in any DNSBLs"] else "Likely safe"
        }
    
    elif input_type == 'sha256':
        sha256 = request.form.get('sha256')
        if not sha256:
            return render_template('error.html', message="No SHA256 provided")
        # Note: VirusTotal SHA256 lookup requires a valid hash and API call (simplified here)
        results = {
            "sha256": sha256,
            "verdict": "Unable to verify SHA256 (API lookup not implemented for simplicity)"
        }
    
    return render_template('results.html', results=results, input_type=input_type)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)