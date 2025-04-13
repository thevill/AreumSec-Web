# utils/threat_intel.py
import ipaddress
import dns.resolver
import dns.exception
import whois
from ipwhois import IPWhois
import requests
import urllib.request
import urllib.parse
import json
from config import Config
from models import DNSBL, db

def check_ip_dnsbl(ip_address):
    try:
        ip_version = ipaddress.ip_address(ip_address).version
        listed_dnsbls = []
        
        # Fetch DNSBLs from database
        dnsbls = DNSBL.query.all()
        for dnsbl in dnsbls:
            try:
                if ip_version == 4:
                    query = '.'.join(reversed(str(ip_address).split("."))) + "." + dnsbl.name
                else:
                    query = '.'.join(reversed(str(ip_address).replace(':', ''))) + "." + dnsbl.name
                dns.resolver.resolve(query, 'A')
                listed_dnsbls.append(dnsbl.name)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.DNSException:
                pass
        
        return listed_dnsbls if listed_dnsbls else ["Not listed in any DNSBLs"]
    except Exception:
        return ["Invalid IP address"]

def check_organization(sender_ip, sender_domain):
    if not sender_ip or not sender_domain:
        return "Missing IP or domain"
    
    try:
        ip_version = ipaddress.ip_address(sender_ip).version
        ip_info = None
        
        if ip_version == 4:
            ip_info = whois.whois(sender_ip)
            ip_org = str(ip_info.get('org', '')).lower()
        else:
            try:
                ip = IPWhois(sender_ip)
                result = ip.lookup_rdap()
                ip_org = result.get('network', {}).get('entities', [{}])[0].get('name', '').lower()
            except Exception:
                ip_org = ''
        
        domain_info = whois.whois(sender_domain)
        domain_org = str(domain_info.get('org', '')).lower()
        
        if ip_org and domain_org and ip_org == domain_org:
            return "IP and domain belong to the same organization"
        return "IP and domain do not belong to the same organization"
    except Exception:
        return "Unable to fetch organization info"

def query_virustotal(url):
    params = {'apikey': Config.VIRUSTOTAL_API_KEY, 'resource': url, 'allinfo': 'true'}
    headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip, Python VT client"}
    
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        json_response = response.json()
        
        if json_response['response_code'] == 1:
            verdict = "Malicious" if json_response['positives'] > 0 else "Not malicious"
            engines = json_response['scans']
            top_engines = sorted(engines.items(), key=lambda x: x[1]['detected'], reverse=True)[:5]
            engine_list = [f"{engine[0]}: {engine[1]['result']}" for engine in top_engines]
            return {"verdict": verdict, "engines": engine_list}
        return {"verdict": f"Error: {json_response['verbose_msg']}", "engines": []}
    except Exception as e:
        return {"verdict": f"Error querying VirusTotal: {e}", "engines": []}

# utils/threat_intel.py
def query_virustotal_file(file_path, sha256_hash):
    params = {'apikey': Config.VIRUSTOTAL_API_KEY, 'resource': sha256_hash, 'allinfo': 'true'}
    headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip, Python VT client"}
    
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors (e.g., 403, 404)
        json_response = response.json()
        
        if json_response['response_code'] == 1:
            verdict = "Malicious" if json_response['positives'] > 0 else "Not malicious"
            engines = json_response.get('scans', {})
            top_engines = sorted(engines.items(), key=lambda x: x[1]['detected'], reverse=True)[:5]
            engine_list = [f"{engine[0]}: {engine[1]['result']}" for engine in top_engines]
            file_history = json_response.get('additional_info', {}).get('submissions', [])
            file_history_list = [f"Date: {entry['date']}, Verdict: {entry['result']}" for entry in file_history] or ["No history available"]
            return {"verdict": verdict, "engines": engine_list, "history": file_history_list}
        else:
            return {"verdict": f"Error: {json_response.get('verbose_msg', 'Unknown error')}", "engines": [], "history": []}
    
    except requests.exceptions.HTTPError as e:
        return {"verdict": f"HTTP Error querying VirusTotal: {e}", "engines": [], "history": []}
    except requests.exceptions.ConnectionError:
        return {"verdict": "Error: Failed to connect to VirusTotal", "engines": [], "history": []}
    except ValueError:
        return {"verdict": "Error: Invalid response from VirusTotal", "engines": [], "history": []}
    except Exception as e:
        return {"verdict": f"Unexpected error querying VirusTotal: {e}", "engines": [], "history": []}
    

    

def query_safe_browsing_url(url):
    for api_key in Config.GOOGLE_SAFE_BROWSING_API_KEYS:
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        encoded_url = urllib.parse.quote(str(url))
        payload = {
            'client': {'clientId': 'myapp', 'clientVersion': '1.5.2'},
            'threatInfo': {
                'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': encoded_url}]
            }
        }
        
        try:
            response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
            threat_info = response.json()
            return "Malicious" if threat_info.get('matches') else "Not malicious"
        except Exception:
            continue
    return "Error querying Safe Browsing"