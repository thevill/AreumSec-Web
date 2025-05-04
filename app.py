#Developed by Pranay Wajjala

import re
import requests
import time
from datetime import datetime, timedelta
import os
import pickle
import binascii
import socket
import json
import logging
import sqlite3
from email import message_from_file
from urllib.parse import urlparse, quote
import ipaddress
import dns.resolver
import dns.exception
import whois
from ipwhois import IPWhois
import hashlib
from flask import Flask, render_template, request, redirect, url_for
from flask_bootstrap import Bootstrap
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# Flask app setup
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.urandom(24)
bootstrap = Bootstrap(app)

# Cache and logging setup
CACHE_FILE = "url_cache.pkl"
LOG_FILE = "app.log"
MAX_PULLS = 5
TIME_WINDOW = 24 * 60 * 60  # 24 hours in seconds
DATABASE = "results.db"
RESULTS_PER_PAGE = 10
UPLOAD_FOLDER = "Uploads"
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB in bytes (VirusTotal limit)

# API limits
VIRUSTOTAL_LIMITS = {'daily': 500, 'minute': 4}
GOOGLE_SB_LIMITS = {'daily': 10000}

# Logging configuration
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS results
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         url TEXT NOT NULL,
                         service TEXT NOT NULL,
                         result TEXT NOT NULL,
                         timestamp TEXT NOT NULL)''')
        conn.commit()

# Load config
def load_config():
    config = {'virustotal_api_keys': [], 'google_safe_browsing_api_keys': []}
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config.update(json.load(f))
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
    return config

# Initialize cache
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'rb') as f:
            return pickle.load(f)
    return {
        'urls': set(),
        'access_log': [],
        'virustotal_usage': {},
        'google_sb_usage': {}
    }

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(cache, f)
    except Exception as e:
        logging.error(f"Failed to save cache: {e}")

# Validate URL format
def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in ['http', 'https']

# Validate IP format
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Validate SHA256 format
def is_valid_sha256(sha256):
    regex = re.compile(r'^[a-fA-F0-9]{64}$')
    return regex.match(sha256) is not None

# Check internet connectivity
def is_online():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError as e:
        logging.error(f"Internet connectivity check failed: {e}")
        return False

# Check rate limit for URLhaus
def can_pull(cache):
    now = datetime.now()
    access_log = cache['access_log']
    access_log = [t for t in access_log if (now - t).total_seconds() < TIME_WINDOW]
    cache['access_log'] = access_log
    if len(access_log) >= MAX_PULLS:
        return False
    cache['access_log'].append(now)
    save_cache(cache)
    return True

# Check API key limits
def can_use_api_key(cache, api_key, service, now):
    limits = VIRUSTOTAL_LIMITS if service == 'virustotal' else GOOGLE_SB_LIMITS
    usage = cache[f'{service}_usage'].setdefault(api_key, {'daily': [], 'minute': []} if service == 'virustotal' else {'daily': []})
    
    for period in usage:
        if period == 'daily':
            usage[period] = [t for t in usage[period] if (now - t[0]).total_seconds() < TIME_WINDOW]
        elif period == 'minute':
            usage[period] = [t for t in usage[period] if (now - t[0]).total_seconds() < 60]
    
    daily_count = sum(c for _, c in usage['daily'])
    minute_count = sum(c for _, c in usage.get('minute', [])) if service == 'virustotal' else 0
    
    if daily_count >= limits['daily'] or (service == 'virustotal' and minute_count >= limits['minute']):
        return False
    
    usage['daily'].append((now, 1))
    if service == 'virustotal':
        usage['minute'].append((now, 1))
    save_cache(cache)
    return True

# Check URL against URLhaus text list
def check_urlhaus_text(url, cache):
    if url in cache['urls']:
        return True
    if not can_pull(cache):
        return "Rate limit exceeded. Try again later."
    
    try:
        response = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and is_valid_url(line):
                cache['urls'].add(line)
                if line == url:
                    save_cache(cache)
                    return True
        save_cache(cache)
        return False
    except requests.RequestException as e:
        logging.error(f"URLhaus text list error: {e}")
        return f"Error accessing URLhaus text list: {e}"

# Check URL against URLhaus ClamAV signatures
def check_urlhaus_ndb(url, cache):
    if url in cache['urls']:
        return True
    if not can_pull(cache):
        return "Rate limit exceeded. Try again later."
    
    try:
        response = requests.get("https://urlhaus.abuse.ch/downloads/urlhaus.ndb", timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        for line in lines:
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) == 5:
                    hex_signature = parts[3].strip()
                    try:
                        decoded_url = binascii.unhexlify(hex_signature).decode('utf-8').strip()
                        if is_valid_url(decoded_url):
                            cache['urls'].add(decoded_url)
                            if decoded_url == url:
                                save_cache(cache)
                                return True
                    except (binascii.Error, UnicodeDecodeError) as e:
                        logging.error(f"URLhaus NDB decode error: {e}")
                        continue
        save_cache(cache)
        return False
    except requests.RequestException as e:
        logging.error(f"URLhaus NDB error: {e}")
        return f"Error accessing URLhaus NDB: {e}"

# Check VirusTotal for URL
def query_virustotal_url(url, config, cache):
    api_keys = config.get('virustotal_api_keys', [])
    if not api_keys:
        return {"verdict": "Error: No VirusTotal API keys configured.", "engines": []}
    
    now = datetime.now()
    for api_key in api_keys:
        if not can_use_api_key(cache, api_key, 'virustotal', now):
            continue
        params = {'apikey': api_key, 'resource': url, 'allinfo': 'true'}
        headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip, Python VT client"}
        
        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers, timeout=10)
            response.raise_for_status()
            json_response = response.json()
            if json_response['response_code'] == 1:
                verdict = "Suspicious" if json_response['positives'] > 0 else "Clean"
                engines = [f"{engine}: {result['result']}" for engine, result in json_response['scans'].items() if result['detected']][:5]
                return {"verdict": verdict, "engines": engines}
            return {"verdict": f"Error: {json_response['verbose_msg']}", "engines": []}
        except requests.RequestException as e:
            logging.error(f"VirusTotal URL error with key {api_key}: {e}")
            return {"verdict": f"Error: {e}", "engines": []}
    
    return {"verdict": "Error: All VirusTotal API keys have reached their rate limit.", "engines": []}

# Check VirusTotal for File
def query_virustotal_file(file_path, config, cache):
    api_keys = config.get('virustotal_api_keys', [])
    if not api_keys:
        return {"verdict": "Error: No VirusTotal API keys configured.", "engines": [], "history": []}
    
    sha256_hash = calculate_sha256(file_path)
    now = datetime.now()
    for api_key in api_keys:
        if not can_use_api_key(cache, api_key, 'virustotal', now):
            continue
        params = {'apikey': api_key, 'resource': sha256_hash, 'allinfo': 'true'}
        headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip, Python VT client"}
        
        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers, timeout=10)
            response.raise_for_status()
            json_response = response.json()
            if json_response['response_code'] == 1:
                verdict = "Suspicious" if json_response['positives'] > 0 else "Clean"
                engines = [f"{engine}: {result['result']}" for engine, result in json_response['scans'].items() if result['detected']][:5]
                file_history = json_response.get('additional_info', {}).get('submissions', [])
                history = [f"Date: {entry['date']}, Verdict: {entry['result']}" for entry in file_history] if file_history else ["No submission history."]
                return {"verdict": verdict, "engines": engines, "history": history}
            return {"verdict": f"Error: {json_response['verbose_msg']}", "engines": [], "history": []}
        except requests.RequestException as e:
            logging.error(f"VirusTotal file error with key {api_key}: {e}")
            return {"verdict": f"Error: {e}", "engines": [], "history": []}
    
    return {"verdict": "Error: All VirusTotal API keys have reached their rate limit.", "engines": [], "history": []}

# Check VirusTotal for SHA256
def query_virustotal_sha256(sha256, config, cache):
    api_keys = config.get('virustotal_api_keys', [])
    if not api_keys:
        return {"verdict": "Error: No VirusTotal API keys configured.", "engines": []}
    
    now = datetime.now()
    for api_key in api_keys:
        if not can_use_api_key(cache, api_key, 'virustotal', now):
            continue
        api_url = f'https://www.virustotal.com/api/v3/files/{sha256}'
        headers = {'x-apikey': api_key}
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            url_info = response.json()
            if 'data' in url_info and 'attributes' in url_info['data'] and 'last_analysis_stats' in url_info['data']['attributes']:
                verdict = "Suspicious" if url_info['data']['attributes']['last_analysis_stats']['malicious'] > 0 else "Clean"
                engines = [f"{engine}: {result['result']}" for engine, result in url_info['data']['attributes']['last_analysis_results'].items() if result['category'] == 'malicious'][:5]
                return {"verdict": verdict, "engines": engines}
            return {"verdict": "Unknown SHA256", "engines": []}
        except requests.RequestException as e:
            logging.error(f"VirusTotal SHA256 error with key {api_key}: {e}")
            return {"verdict": f"Error: {e}", "engines": []}
    
    return {"verdict": "Error: All VirusTotal API keys have reached their rate limit.", "engines": []}

# Check Google Safe Browsing
def query_safe_browsing_url(url, config, cache):
    api_keys = config.get('google_safe_browsing_api_keys', [])
    if not api_keys:
        return "Error: No Google Safe Browsing API keys configured."
    
    now = datetime.now()
    for api_key in api_keys:
        if not can_use_api_key(cache, api_key, 'google_sb', now):
            continue
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        encoded_url = quote(url)
        payload = {
            'client': {'clientId': 'areumsec', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': encoded_url}]
            }
        }
        
        try:
            response = requests.post(api_url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            return "Suspicious" if 'matches' in result and len(result['matches']) > 0 else "Clean"
        except requests.RequestException as e:
            logging.error(f"Google Safe Browsing error with key {api_key}: {e}")
            return f"Error: {e}"
    
    return "Error: All Google Safe Browsing API keys have reached their rate limit."

# Check DNSBL for IP
def check_ip_dnsbl(ip_address):
    dnsbls = [
        "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net", "xbl.spamhaus.org",
        "z.mailspike.net", "zombie.dnsbl.sorbs.net", "multi.surbl.org", "dnsbl.invaluement.com",
        "b.barracudacentral.org", "blacklist.woody.ch", "bogons.cymru.com", "cbl.abuseat.org",
        "combined.abuse.ch", "db.wpbl.info", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
        "dnsbl-3.uceprotect.net", "dnsbl.dronebl.org", "drone.abuse.ch", "duinv.aupads.org",
        "dul.dnsbl.sorbs.net", "dyna.spamrats.com", "http.dnsbl.sorbs.net", "ips.backscatterer.org",
        "ix.dnsbl.manitu.net", "korea.services.net", "misc.dnsbl.sorbs.net", "noptr.spamrats.com",
        "orvedb.aupads.org", "pbl.spamhaus.org", "proxy.bl.gweep.ca", "psbl.surriel.com",
        "relays.bl.gweep.ca", "relays.nether.net", "sbl.spamhaus.org", "singular.ttk.pte.hu",
        "smtp.dnsbl.sorbs.net", "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.anonmails.de",
        "spam.dnsbl.sorbs.net", "spam.spamrats.com", "spambot.bls.digibase.ca", "spamrbl.imp.ch",
        "spamsources.fabel.dk", "ubl.lashback.com", "ubl.unsubscore.com", "virus.rbl.jp",
        "web.dnsbl.sorbs.net", "wormrbl.imp.ch"
    ]
    listed_dnsbls = []
    
    try:
        ip_version = ipaddress.ip_address(ip_address).version
        for dnsbl in dnsbls:
            try:
                if ip_version == 4:
                    query = '.'.join(reversed(str(ip_address).split("."))) + "." + dnsbl
                else:
                    query = '.'.join(reversed(str(ip_address).replace(':', ''))) + "." + dnsbl
                dns.resolver.resolve(query, 'A')
                listed_dnsbls.append(dnsbl)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
        return f"Listed in: {', '.join(listed_dnsbls)}" if listed_dnsbls else "Not listed in any DNSBLs"
    except ValueError:
        return "Invalid IP address"

# Check organization
def check_organization(sender_ip, sender_domain):
    if not sender_ip:
        return "Unable to identify the organization from the IP/Domain"
    
    try:
        if not is_valid_ip(sender_ip):
            return "Invalid IP address"
        
        ip_version = ipaddress.ip_address(sender_ip).version
        ip_info = None
        
        if ip_version == 4:
            ip_info = whois.whois(sender_ip)
        else:
            try:
                ip = IPWhois(sender_ip)
                result = ip.lookup_rdap()
                ip_info = result.get('network', {}).get('name', '')
            except Exception as e:
                return f"Error fetching IPv6 organization information: {e}"
        
        domain_info = whois.whois(sender_domain) if sender_domain else None
        
        if not ip_info or not domain_info:
            return "Unable to identify the organization from the IP/Domain"
        
        ip_org = str(ip_info.get('org', '')).lower() if ip_version == 4 else ip_info.lower()
        domain_org = str(domain_info.get('org', '')).lower() if domain_info else ''
        
        if ip_org and domain_org and ip_org == domain_org:
            return "Sender IP and Domain belong to the same Organization"
        return "Sender IP and Domain do not belong to the same Organization"
    
    except Exception as e:
        return f"Error fetching WHOIS information: {e}"

# Check if file is an email with headers
def is_email_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read(1024)  # Read first 1KB to check for headers
            return bool(re.search(r'^(From|Subject|Received|To|Date):', content, re.MULTILINE | re.IGNORECASE))
    except Exception:
        return False

# Extract email data
def extract_email_data(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            msg = message_from_file(file)
        
        # Sender info
        p1_sender = ""
        p1_sender_headers = ["X-Mailfrom", "Return-path", "X-Original-Return-Path"]
        for header in p1_sender_headers:
            p1_sender = msg.get(header, "")
            if p1_sender:
                break
        p2_sender = msg.get("From", "").strip()
        sender_domain = p2_sender.split('@')[-1].split('>')[0].strip() if '@' in p2_sender else ""
        
        # Subject
        subject = msg.get("Subject", "")
        
        # Sender IP
        headers = str(msg)
        ip_match = re.search(r'Received:.*\[(.*?)\]', headers)
        sender_ip = ip_match.group(1) if ip_match else None
        
        # Authentication results
        header = msg.get("Authentication-Results", "")
        auth_results = {"SPF": "Not found", "DKIM": "Not found", "DMARC": "Not found"}
        if header:
            spf_match = re.search(r'spf=([^\s;]+)', header)
            dkim_match = re.search(r'dkim=([^\s;]+)', header)
            dmarc_match = re.search(r'dmarc=([^\s;]+)', header)
            auth_results["SPF"] = spf_match.group(1) if spf_match else "Not found"
            auth_results["DKIM"] = dkim_match.group(1) if dkim_match else "Not found"
            auth_results["DMARC"] = dmarc_match.group(1) if dmarc_match else "Not found"
        
        # URLs
        urls = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ['text/plain', 'text/html']:
                    content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    urls += re.findall(r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)', content)
        else:
            content = msg.get_payload(decode=True).decode('utf-8', errors='ignore') if msg.get_payload() else ""
            urls += re.findall(r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)', content)
        urls = list(set(urlparse(url).geturl() for url in urls)) if urls else ["No URLs found"]
        
        return {
            'p1_sender': p1_sender,
            'p2_sender': p2_sender,
            'sender_domain': sender_domain,
            'sender_ip': sender_ip,
            'subject': subject,
            'auth_data': auth_results,
            'urls': urls
        }
    except Exception as e:
        logging.error(f"Error parsing email file: {e}")
        return None

# Calculate SHA256 hash
def calculate_sha256(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                sha256_hash.update(data)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating SHA256 hash: {e}")
        return None

# Check file size
def check_file_size(file):
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    return size <= MAX_FILE_SIZE

# Log result to database
def log_result(url, service, result):
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute(
                "INSERT INTO results (url, service, result, timestamp) VALUES (?, ?, ?, ?)",
                (url, service, result, datetime.now().isoformat())
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")

@app.route('/', methods=['GET'])
def index():
    cache = load_cache()
    online = is_online()
    cached = bool(cache['urls'])
    config = load_config()
    has_vt_keys = bool(config.get('virustotal_api_keys'))
    has_gsb_keys = bool(config.get('google_safe_browsing_api_keys'))
    return render_template('index.html', online=online, cached=cached, has_vt_keys=has_vt_keys, has_gsb_keys=has_gsb_keys)

@app.route('/analyze', methods=['POST'])
def analyze():
    cache = load_cache()
    config = load_config()
    online = is_online()
    input_type = request.form.get('input_type')
    
    if not online and input_type != 'url':
        return render_template('error.html', message="No internet connection. Only URLhaus checks are available offline.")
    
    results = {}
    verdict = "Clean"
    
    if input_type == 'file':
        if 'file' not in request.files:
            return render_template('error.html', message="No file uploaded.")
        file = request.files['file']
        if file.filename == '':
            return render_template('error.html', message="No file selected.")
        
        # Check file size
        if not check_file_size(file):
            return render_template('error.html', message="File size exceeds 32 MB (VirusTotal limit).")
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        results['file'] = filename
        file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        # Check if file is .eml, .msg, or .txt with email headers
        is_email = file_extension in ['eml', 'msg', 'txt'] and is_email_file(file_path)
        
        if is_email:
            if not config.get('virustotal_api_keys') or not config.get('google_safe_browsing_api_keys'):
                os.remove(file_path)
                return render_template('error.html', message="VirusTotal and Google Safe Browsing API keys required for email file analysis.")
            
            email_data = extract_email_data(file_path)
            if not email_data:
                os.remove(file_path)
                return render_template('error.html', message="Error parsing email file.")
            
            results.update(email_data)
            results['organization'] = check_organization(results['sender_ip'], results['sender_domain']) if results['sender_ip'] else "No sender IP"
            results['dnsbl'] = check_ip_dnsbl(results['sender_ip']) if results['sender_ip'] and is_valid_ip(results['sender_ip']) else "Invalid or no IP"
            
            if results['urls'] != ["No URLs found"]:
                url_results = []
                for url in results['urls']:
                    vt_result = query_virustotal_url(url, config, cache)
                    gsb_result = query_safe_browsing_url(url, config, cache)
                    url_results.append({
                        'url': url,
                        'virustotal': vt_result,
                        'safebrowsing': gsb_result
                    })
                    if vt_result['verdict'] == "Suspicious" or gsb_result == "Suspicious":
                        verdict = "Suspicious"
                results['urls'] = url_results
            else:
                results['urls'] = "No URLs found"
        
        # VirusTotal file analysis (for all files)
        if not config.get('virustotal_api_keys'):
            results['vt_file'] = {"verdict": "Error: No VirusTotal API keys configured.", "engines": [], "history": []}
        else:
            results['vt_file'] = query_virustotal_file(file_path, config, cache)
            if results['vt_file']['verdict'] == "Suspicious":
                verdict = "Suspicious"
        
        # Verdict for email files
        if is_email and (results['dnsbl'].startswith("Listed in:") or
                         results['organization'] == "Sender IP and Domain do not belong to the same Organization"):
            verdict = "Suspicious"
        
        results['verdict'] = verdict
        results['is_email'] = is_email
        
        log_result(filename, "File Analysis", f"Verdict: {verdict}")
        os.remove(file_path)
    
    elif input_type == 'url':
        url = request.form.get('url', '').strip()
        service = request.form.get('service', 'URLhaus')
        if not is_valid_url(url):
            return render_template('error.html', message="Invalid URL format.")
        
        results['url'] = url
        if service == 'All 3' and online:
            if not config.get('virustotal_api_keys') or not config.get('google_safe_browsing_api_keys'):
                return render_template('error.html', message="VirusTotal and Google Safe Browsing API keys required for All 3 services.")
            results['virustotal'] = query_virustotal_url(url, config, cache)
            results['safebrowsing'] = query_safe_browsing_url(url, config, cache)
            uh_text = check_urlhaus_text(url, cache)
            uh_result = uh_text
            if uh_text is False:
                uh_result = check_urlhaus_ndb(url, cache)
            results['urlhaus'] = {"verdict": "Suspicious" if uh_result is True else "Clean" if uh_result is False else f"Error: {uh_result}"}
            verdict = "Suspicious" if results['virustotal']['verdict'] == "Suspicious" or results['safebrowsing'] == "Suspicious" or results['urlhaus']['verdict'] == "Suspicious" else "Clean"
            log_result(url, "All 3", f"VirusTotal: {results['virustotal']['verdict']}, Safe Browsing: {results['safebrowsing']}, URLhaus: {results['urlhaus']['verdict']}")
        elif service == 'VirusTotal' and online:
            if not config.get('virustotal_api_keys'):
                return render_template('error.html', message="VirusTotal API key required.")
            results['virustotal'] = query_virustotal_url(url, config, cache)
            results['safebrowsing'] = "Not checked"
            results['urlhaus'] = {"verdict": "Not checked"}
            verdict = results['virustotal']['verdict']
            log_result(url, "VirusTotal", f"VirusTotal: {verdict}")
        elif service == 'Google Safe Browsing' and online:
            if not config.get('google_safe_browsing_api_keys'):
                return render_template('error.html', message="Google Safe Browsing API key required.")
            results['virustotal'] = {"verdict": "Not checked", "engines": []}
            results['safebrowsing'] = query_safe_browsing_url(url, config, cache)
            results['urlhaus'] = {"verdict": "Not checked"}
            verdict = results['safebrowsing']
            log_result(url, "Google Safe Browsing", f"Safe Browsing: {verdict}")
        elif service == 'URLhaus':
            results['virustotal'] = {"verdict": "Not checked", "engines": []}
            results['safebrowsing'] = "Not checked"
            uh_text = check_urlhaus_text(url, cache)
            if uh_text is True:
                results['urlhaus'] = {"verdict": "Suspicious"}
                verdict = "Suspicious"
            elif isinstance(uh_text, str):
                results['urlhaus'] = {"verdict": f"Error: {uh_text}"}
                verdict = "Error"
            else:
                uh_ndb = check_urlhaus_ndb(url, cache)
                results['urlhaus'] = {"verdict": "Suspicious" if uh_ndb is True else "Clean" if uh_ndb is False else f"Error: {uh_ndb}"}
                verdict = "Suspicious" if uh_ndb is True else "Clean"
            log_result(url, "URLhaus", f"URLhaus: {results['urlhaus']['verdict']}")
        else:
            return render_template('error.html', message="Service unavailable offline.")
        results['verdict'] = verdict
    
    elif input_type == 'ip':
        ip = request.form.get('ip', '').strip()
        if not is_valid_ip(ip):
            return render_template('error.html', message="Invalid IP format.")
        
        results['ip'] = ip
        results['dnsbl'] = check_ip_dnsbl(ip)
        results['verdict'] = "Suspicious" if results['dnsbl'].startswith("Listed in:") else "Clean"
        
        log_result(ip, "IP Analysis", f"Verdict: {results['verdict']}")
    
    elif input_type == 'sha256':
        if not config.get('virustotal_api_keys'):
            return render_template('error.html', message="VirusTotal API key required for SHA256 analysis.")
        sha256 = request.form.get('sha256', '').strip()
        if not is_valid_sha256(sha256):
            return render_template('error.html', message="Invalid SHA256 format.")
        
        results['sha256'] = sha256
        vt_result = query_virustotal_sha256(sha256, config, cache)
        results['verdict'] = vt_result['verdict']
        results['engines'] = vt_result['engines']
        
        log_result(sha256, "SHA256 Analysis", f"Verdict: {results['verdict']}")
    
    return render_template('results.html', input_type=input_type, results=results)

@app.route('/history')
def history():
    try:
        page = request.args.get('page', 1, type=int)
        sort = request.args.get('sort', 'timestamp', type=str)
        order = request.args.get('order', 'desc', type=str)
        
        valid_columns = ['url', 'service', 'result', 'timestamp']
        if sort not in valid_columns:
            sort = 'timestamp'
        
        if order not in ['asc', 'desc']:
            order = 'desc'
        
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT COUNT(*) FROM results")
            total_results = cursor.fetchone()[0]
            total_pages = (total_results + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
            
            offset = (page - 1) * RESULTS_PER_PAGE
            query = f"SELECT * FROM results ORDER BY {sort} {order} LIMIT ? OFFSET ?"
            cursor = conn.execute(query, (RESULTS_PER_PAGE, offset))
            results = cursor.fetchall()
        
        return render_template('history.html', results=results, page=page, total_pages=total_pages, sort=sort, order=order)
    except sqlite3.Error as e:
        logging.error(f"Database error fetching history: {e}")
        return render_template('error.html', message="Error fetching history. Please try again later.")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
