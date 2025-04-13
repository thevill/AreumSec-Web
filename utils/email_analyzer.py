# utils/email_analyzer.py
import os
import re
import urllib.parse
from email import message_from_file
from pathlib import Path
from urllib.parse import urlparse
import hashlib

def extract_sender_info(file_path):
    p1_sender, p2_sender, sender_domain = "", "", ""
    file_extension = os.path.splitext(file_path)[1].lower()
    
    if file_extension in ['.eml', '.msg', '.txt']:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                msg = message_from_file(file)
            
            p1_sender_headers = ["X-Mailfrom", "Return-path", "X-Original-Return-Path"]
            for header in p1_sender_headers:
                p1_sender = msg.get(header, "")
                if p1_sender:
                    break
            
            from_header = msg.get("From", "")
            if from_header:
                p2_sender = from_header.strip()
                sender_parts = p2_sender.split('@')
                if len(sender_parts) > 1:
                    sender_domain = sender_parts[1].split('>')[0].strip()
                    
            return p1_sender, p2_sender, sender_domain
        except Exception as e:
            return "", "", ""
    return "", "", ""

def extract_sender_ip(file_path):
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in ['.eml', '.msg', '.txt']:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                msg = message_from_file(file)
            headers = str(msg)
            ip_match = re.search(r'Received:.*\[(.*?)\]', headers)
            return ip_match.group(1) if ip_match else None
        except Exception:
            return None
    return None

def extract_subject(file_path):
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in ['.eml', '.msg', '.txt']:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                msg = message_from_file(file)
            return msg.get("Subject", "")
        except Exception:
            return ""
    return ""

def extract_urls(file_path):
    urls = []
    file_extension = Path(file_path).suffix.lower()
    try:
        if file_extension in ['.eml', '.msg']:
            with open(file_path, 'r', encoding='utf-8') as file:
                msg = message_from_file(file)
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type in ['text/plain', 'text/html']:
                        urls += re.findall(
                            r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)',
                            part.get_payload()
                        )
            else:
                urls += re.findall(
                    r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)',
                    msg.get_payload()
                )
        elif file_extension == '.txt':
            with open(file_path, 'r', encoding='utf-8') as file:
                text = file.read()
                urls += re.findall(
                    r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)',
                    text
                )
    except Exception:
        pass
    return urls

def extract_auth_data(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            msg = message_from_file(file)
        header = msg.get("Authentication-Results", "")
        if not header:
            return {"SPF": "Not found", "DKIM": "Not found", "DMARC": "Not found"}
        
        spf_match = re.search(r'spf=([^\s;]+)', header)
        dkim_match = re.search(r'dkim=([^\s;]+)', header)
        dmarc_match = re.search(r'dmarc=([^\s;]+)', header)
        
        return {
            "SPF": spf_match.group(1) if spf_match else "Not found",
            "DKIM": dkim_match.group(1) if dkim_match else "Not found",
            "DMARC": dmarc_match.group(1) if dmarc_match else "Not found"
        }
    except Exception:
        return {"SPF": "Not found", "DKIM": "Not found", "DMARC": "Not found"}

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
    except Exception:
        return None