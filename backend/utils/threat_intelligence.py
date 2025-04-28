import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ThreatIntelligence:
    def __init__(self):
        self.vt_api_key = os.getenv('VT_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        print(f"AbuseIPDB API key loaded: {'Yes' if self.abuseipdb_api_key else 'No'}")
        self.vt_base_url = 'https://www.virustotal.com/vtapi/v2'
        self.abuseipdb_base_url = 'https://api.abuseipdb.com/api/v2'

    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal"""
        if not self.vt_api_key:
            return None

        try:
            params = {'apikey': self.vt_api_key, 'resource': file_hash}
            response = requests.get(f'{self.vt_base_url}/file/report', params=params)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
            return None

    def check_abuseipdb(self, ip_address):
        """Check IP address against AbuseIPDB"""
        if not self.abuseipdb_api_key:
            print(f"No AbuseIPDB API key found for IP: {ip_address}")
            return None

        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
            print(f"Checking IP {ip_address} against AbuseIPDB...")
            response = requests.get(
                f'{self.abuseipdb_base_url}/check',
                headers=headers,
                params=params
            )
            print(f"AbuseIPDB response status: {response.status_code}")
            if response.status_code == 200:
                print(f"Successfully checked IP {ip_address}")
                return response.json()
            print(f"Failed to check IP {ip_address}. Status code: {response.status_code}")
            if response.status_code != 404:
                print(f"Response content: {response.text}")
            return None
        except Exception as e:
            print(f"AbuseIPDB API error for IP {ip_address}: {str(e)}")
            return None

    def calculate_risk_score(self, email_data, vt_results=None, abuseipdb_results=None):
        """Calculate risk score based on various indicators"""
        score = 0
        max_score = 100

        # Suspicious subject patterns (increased weight)
        suspicious_subject_patterns = [
            'login', 'password', 'account', 'verify', 'security',
            'suspicious', 'unauthorized', 'alert', 'warning',
            'urgent', 'action required', 'suspended', 'locked',
            'compromised', 'hack', 'breach', 'verify', 'confirm',
            'dear', 'hello dear', 'good news', 'respond immediately',
            'still in use', 'kindly', 'asap', 'important'
        ]
        subject = email_data.get('subject', '').lower()
        if any(pattern in subject for pattern in suspicious_subject_patterns):
            score += 25  # Increased from 20

        # Suspicious sender domain (increased weight)
        from_addr = email_data.get('from', '').lower()
        suspicious_tlds = ['.ru', '.cn', '.tk', '.xyz', '.sur', '.info', '.biz', '.top', '.work', '.site']
        if any(tld in from_addr for tld in suspicious_tlds):
            score += 20  # Increased from 15

        # Check for same sender/recipient email with different names
        to_addr = email_data.get('to', '').lower()
        if from_addr == to_addr:
            # Extract names from email addresses
            from_name = from_addr.split('@')[0]
            to_name = to_addr.split('@')[0]
            if from_name != to_name:
                score += 30  # New high-risk indicator

        # URL shorteners and suspicious domains
        suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
            'cli.gs', 'ow.ly', 'yfrog.com', 'migre.me', 'ff.im',
            'tiny.cc', 'url4.eu', 'tr.im', 'twit.ac', 'su.pr',
            'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com',
            'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com',
            'fic.kr', 'loopt.us', 'htxt.it', 'AltURL.com', 'RedirX.com'
        ]
        for url in email_data.get('urls', []):
            if any(domain in url.lower() for domain in suspicious_domains):
                score += 15  # Increased from 10

        # VirusTotal results
        if vt_results:
            positives = vt_results.get('positives', 0)
            total = vt_results.get('total', 0)
            if total > 0:
                score += (positives / total) * 25  # Increased from 20

        # AbuseIPDB results (improved scoring)
        if abuseipdb_results:
            for ip, result in abuseipdb_results.items():
                if result and result.get('data'):
                    abuse_score = result['data'].get('abuseConfidenceScore', 0)
                    total_reports = result['data'].get('totalReports', 0)
                    
                    # Base score from abuse confidence
                    score += (abuse_score / 100) * 20  # Increased from 15
                    
                    # Additional points for number of reports
                    score += min(total_reports * 2, 10)  # Up to 10 points for reports
                    
                    # Additional points for known malicious IPs
                    if abuse_score > 50:
                        score += 15  # Increased from 10

        # Server hops analysis (improved)
        for hop in email_data.get('server_hops', []):
            # Check for private IPs
            if any(ip in hop.get('ip_addresses', []) for ip in ['192.168.', '10.', '172.16.']):
                score += 10  # Increased from 5
            
            # Check for suspicious domains in headers
            header = hop.get('header', '').lower()
            if any(domain in header for domain in suspicious_tlds):
                score += 15  # Increased from 10

        # Email content analysis (improved)
        if 'login' in subject and 'account' in subject:
            score += 20  # Increased from 15
        if 'verify' in subject or 'security' in subject:
            score += 15  # Increased from 10

        # Additional checks for common phishing patterns
        if 'user id' in subject.lower() or 'userid' in subject.lower():
            score += 15
        if 'urgent' in subject.lower() or 'immediate' in subject.lower():
            score += 10
        if 'suspended' in subject.lower() or 'locked' in subject.lower():
            score += 15

        # Check for mismatched sender/recipient
        if 'fb' in from_addr.lower() and 'facebook' not in from_addr.lower():
            score += 20

        # Check for common scam patterns
        if 'dear' in subject.lower() and 'good news' in subject.lower():
            score += 25
        if 'still in use' in subject.lower():
            score += 20
        if 'respond immediately' in subject.lower():
            score += 15

        return min(score, max_score) 