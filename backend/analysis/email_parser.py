import email
import re
from email.parser import BytesParser
from email.policy import default

def extract_urls(text):
    """Extract URLs from text using regex"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def extract_ip_addresses(text):
    """Extract IP addresses from text using regex"""
    # Match both IPv4 and IPv6 addresses with more patterns
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    
    # Common patterns in email headers
    patterns = [
        r'from\s+\[?(' + ipv4_pattern + r')\]?',  # from [IP]
        r'by\s+\[?(' + ipv4_pattern + r')\]?',    # by [IP]
        r'for\s+\[?(' + ipv4_pattern + r')\]?',   # for [IP]
        r'id\s+\[?(' + ipv4_pattern + r')\]?',    # id [IP]
        r'\[(' + ipv4_pattern + r')\]',           # [IP]
        ipv4_pattern,                              # raw IP
        ipv6_pattern                               # IPv6
    ]
    
    ips = set()
    print(f"\nAnalyzing text for IP addresses:\n{text}\n")
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            print(f"Found matches with pattern '{pattern}': {matches}")
            if isinstance(matches[0], tuple):
                # Extract non-empty groups from tuple matches
                for match in matches:
                    ips.update(m for m in match if m)
            else:
                ips.update(matches)
    
    # Filter out invalid IPs (basic validation)
    valid_ips = set()
    for ip in ips:
        try:
            # Basic IPv4 validation
            parts = ip.split('.')
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                valid_ips.add(ip)
                print(f"Valid IP found: {ip}")
            else:
                print(f"Invalid IP found: {ip}")
        except:
            # If it fails IPv4 validation, assume it's IPv6 and add it
            valid_ips.add(ip)
            print(f"Assuming IPv6 address: {ip}")
    
    print(f"Final valid IPs: {list(valid_ips)}\n")
    return list(valid_ips)

def parse_email(eml_content):
    """Parse .eml file content and extract relevant information"""
    print("Starting email parsing...")
    # Parse the email content
    msg = BytesParser(policy=default).parsebytes(eml_content)
    
    # Extract basic information
    subject = msg.get('subject', '')
    from_addr = msg.get('from', '')
    to_addr = msg.get('to', '')
    
    print(f"Processing email - Subject: {subject}")
    
    # Extract URLs from body
    urls = []
    plain_text = ""
    html_text = ""
    attachments = []
    suspicious_html_elements = []
    suspicious_language_patterns = []
    phishing_keywords = [
        r'urgent', r'immediately', r'verify your account', r'click here', r'password', r'login', r'update', r'security notice', r'confirm', r'account', r'alert', r'important', r'limited time', r'action required', r'locked', r'suspend', r'phishing', r'bank', r'credit card', r'paypal', r'confirm your identity'
    ]
    html_suspicious_tags = [r'<script', r'<iframe', r'<object', r'<embed', r'<form', r'onerror', r'onload']

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = part.get("Content-Disposition", "").lower()
            if ctype == "text/plain":
                text = part.get_content()
                plain_text += text + "\n"
                urls.extend(extract_urls(text))
            elif ctype == "text/html":
                html = part.get_content()
                html_text += html + "\n"
                urls.extend(extract_urls(html))
                # Suspicious HTML detection
                for tag in html_suspicious_tags:
                    if re.search(tag, html, re.IGNORECASE):
                        suspicious_html_elements.append(tag)
            # Attachment extraction
            if cdisp.startswith("attachment"):
                filename = part.get_filename()
                content_bytes = part.get_payload(decode=True)
                attachments.append({
                    'filename': filename,
                    'content_type': ctype,
                    'content_bytes': content_bytes
                })
    else:
        text = msg.get_content()
        plain_text += text + "\n"
        urls.extend(extract_urls(text))

    # Suspicious language detection (plain text and html)
    for keyword in phishing_keywords:
        if re.search(keyword, plain_text, re.IGNORECASE) or re.search(keyword, html_text, re.IGNORECASE):
            suspicious_language_patterns.append(keyword)
    
    # Extract server hops from Received headers
    server_hops = []
    print("Extracting server hops and IP addresses...")
    
    # Get all headers that might contain IP addresses
    ip_headers = []
    ip_headers.extend(msg.get_all('received', []))
    ip_headers.extend(msg.get_all('x-originating-ip', []))
    ip_headers.extend(msg.get_all('x-sender-ip', []))
    
    print(f"Found {len(ip_headers)} headers that might contain IP addresses")
    
    for header in ip_headers:
        print(f"Processing header: {header}")
        # Extract IP addresses from header
        ips = extract_ip_addresses(header)
        # Filter out IPs that look like dates (e.g., 04.08.07.10)
        filtered_ips = [ip for ip in ips if not re.match(r"^(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})$", ip)]
        if filtered_ips:
            server_hops.append({
                'header': header,
                'ip_addresses': filtered_ips
            })
    
    print(f"Found {len(server_hops)} server hops with IP addresses")

    # --- SPF, DKIM, DMARC Extraction ---
    spf_result = {'result': 'unknown', 'status': 'error'}
    dkim_result = {'result': 'unknown', 'status': 'error'}
    dmarc_result = {'result': 'unknown', 'status': 'error'}
    
    # Try to extract from Authentication-Results
    auth_results = msg.get_all('Authentication-Results', [])
    if auth_results:
        for auth in auth_results:
            # SPF
            spf_match = re.search(r'spf=(pass|fail|neutral|softfail|none|permerror|temperror)', auth, re.IGNORECASE)
            if spf_match:
                spf_result['result'] = spf_match.group(1).lower()
                spf_result['status'] = 'ok' if spf_result['result'] == 'pass' else 'fail'
            # DKIM
            dkim_match = re.search(r'dkim=(pass|fail|neutral|none|policy|temperror|permerror)', auth, re.IGNORECASE)
            if dkim_match:
                dkim_val = dkim_match.group(1).lower()
                dkim_result['result'] = dkim_val
                dkim_result['status'] = 'ok' if dkim_val == 'pass' else 'fail'
            # DMARC
            dmarc_match = re.search(r'dmarc=(pass|fail|bestguesspass|none|policy|temperror|permerror)', auth, re.IGNORECASE)
            if dmarc_match:
                dmarc_result['result'] = dmarc_match.group(1).lower()
                dmarc_result['status'] = 'ok' if dmarc_result['result'] == 'pass' else 'fail'
    # Fallback: Received-SPF
    if spf_result['result'] == 'unknown':
        spf_header = msg.get('Received-SPF', '')
        spf_match = re.search(r'(pass|fail|neutral|softfail|none|permerror|temperror)', spf_header, re.IGNORECASE)
        if spf_match:
            spf_result['result'] = spf_match.group(1).lower()
            spf_result['status'] = 'ok' if spf_result['result'] == 'pass' else 'fail'
    # Fallback: DKIM-Signature (not a result, but presence means signed)
    if dkim_result['result'] == 'unknown':
        dkim_sig = msg.get('DKIM-Signature', None)
        if dkim_sig:
            dkim_result['result'] = 'signed'
            dkim_result['status'] = 'signed'
    # Fallback: DMARC (not usually present as a header)
    # (No fallback for DMARC)

    # --- Risk Assessment ---
    risk_score = 0
    risk_factors = []
    # Failed SPF, DKIM, DMARC
    if spf_result['result'] != 'pass':
        risk_score += 20
        risk_factors.append('SPF failed or not present')
    if dkim_result['result'] != 'pass':
        risk_score += 20
        risk_factors.append('DKIM failed or not present')
    if dmarc_result['result'] != 'pass':
        risk_score += 20
        risk_factors.append('DMARC failed or not present')
    # Suspicious URLs
    if urls:
        risk_score += 10
        risk_factors.append('Suspicious URLs found')
    # Suspicious HTML
    if suspicious_html_elements:
        risk_score += 10
        risk_factors.append('Suspicious HTML elements found')
    # Suspicious language
    if suspicious_language_patterns:
        risk_score += 10
        risk_factors.append('Suspicious language patterns found')
    # Attachments
    if attachments:
        risk_score += 10
        risk_factors.append('Attachments found')
    # Clamp risk score to 100
    risk_score = min(risk_score, 100)
    if risk_score >= 70:
        risk_level = 'high'
    elif risk_score >= 40:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    result = {
        'subject': subject,
        'from': from_addr,
        'to': to_addr,
        'urls': list(set(urls)),  # Remove duplicates
        'server_hops': server_hops,
        'spf': spf_result,
        'dkim': dkim_result,
        'dmarc': dmarc_result,
        'attachments': {'attachments': attachments},
        'html_content': {'suspicious_elements': suspicious_html_elements},
        'language': {'suspicious_patterns': suspicious_language_patterns, 'language': 'unknown'},
        'risk_assessment': {'score': risk_score, 'level': risk_level, 'factors': risk_factors}
    }
    print(f"Parsing complete. Result: {result}")
    return result 