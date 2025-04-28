import re
import hashlib
import magic
from email.parser import BytesParser, Parser
from email.policy import default
from bs4 import BeautifulSoup
import spf
import dkim
import dmarc

class EnhancedEmailAnalysis:
    def __init__(self):
        self.suspicious_patterns = {
            'urgency': [
                'urgent', 'immediate', 'asap', 'right away', 'act now',
                'limited time', 'expires', 'last chance', 'final notice'
            ],
            'authority': [
                'official', 'verify', 'confirm', 'validate', 'secure',
                'authorized', 'legitimate', 'genuine', 'authentic'
            ],
            'fear': [
                'suspended', 'locked', 'compromised', 'hacked', 'breach',
                'unauthorized', 'suspicious', 'alert', 'warning'
            ],
            'greed': [
                'winner', 'prize', 'reward', 'bonus', 'free',
                'discount', 'offer', 'deal', 'savings'
            ]
        }

    def analyze_email(self, eml_content):
        """Perform comprehensive email analysis"""
        if isinstance(eml_content, str):
            msg = Parser(policy=default).parsestr(eml_content)
        else:
            msg = BytesParser(policy=default).parsebytes(eml_content)
        
        # Extract basic email information
        email_info = {
            'subject': msg.get('subject', ''),
            'from': msg.get('from', ''),
            'to': msg.get('to', ''),
            'reply_to': msg.get('reply-to', '')
        }
        
        # Calculate risk score based on various factors
        risk_score = 0
        risk_factors = []
        
        # Check for suspicious subject patterns
        subject = email_info['subject'].lower()
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if pattern in subject:
                    risk_score += 10
                    risk_factors.append(f"Suspicious {category} pattern in subject: {pattern}")
        
        # Check for mismatched sender/recipient
        from_addr = email_info['from']
        reply_to = email_info['reply_to']
        if reply_to and reply_to != from_addr:
            risk_score += 15
            risk_factors.append("Mismatched From and Reply-To addresses")
        
        # Check for same sender and recipient
        to_addr = email_info['to']
        if from_addr and to_addr and from_addr == to_addr:
            risk_score += 20
            risk_factors.append("Sender and recipient are the same")
        
        # Analyze authentication results
        auth_results = msg.get('authentication-results', '')
        spf_result = 'Fail'
        dkim_result = 'Fail'
        dmarc_result = 'Fail'
        
        if 'spf=pass' in auth_results.lower():
            spf_result = 'Pass'
        if 'dkim=pass' in auth_results.lower():
            dkim_result = 'Pass'
        if 'dmarc=pass' in auth_results.lower():
            dmarc_result = 'Pass'
        
        if spf_result == 'Fail':
            risk_score += 15
            risk_factors.append("SPF authentication failed")
        if dkim_result == 'Fail':
            risk_score += 15
            risk_factors.append("DKIM authentication failed")
        if dmarc_result == 'Fail':
            risk_score += 15
            risk_factors.append("DMARC authentication failed")
        
        # Analyze attachments
        attachments = []
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                content_type = part.get_content_type()
                is_suspicious = self._is_suspicious_attachment(content_type, filename)
                attachments.append({
                    'name': filename,
                    'type': content_type,
                    'suspicious': is_suspicious
                })
                if is_suspicious:
                    risk_score += 25
                    risk_factors.append(f"Suspicious attachment: {filename}")
        
        # Analyze HTML content
        suspicious_html = []
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Check for hidden elements
                        hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x)
                        if hidden_elements:
                            suspicious_html.append("Hidden HTML elements found")
                            risk_score += 10
                            risk_factors.append("Hidden HTML elements detected")
                        
                        # Check for suspicious links
                        links = soup.find_all('a')
                        for link in links:
                            href = link.get('href', '')
                            text = link.get_text()
                            if href and text and href not in text:
                                suspicious_html.append(f"Mismatched link text: {text} -> {href}")
                                risk_score += 5
                                risk_factors.append("Mismatched link text detected")
                except:
                    continue
        
        # Analyze email body for suspicious language
        suspicious_language = []
        body = ""
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif part.get_content_type() == 'text/html':
                soup = BeautifulSoup(part.get_payload(decode=True), 'html.parser')
                body += soup.get_text()
        
        body = body.lower()
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if pattern in body:
                    suspicious_language.append(f"{category}: {pattern}")
                    risk_score += 5
                    risk_factors.append(f"Suspicious {category} pattern in body: {pattern}")
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100)
        
        return {
            'email_info': email_info,
            'risk_assessment': {
                'risk_score': risk_score,
                'risk_factors': risk_factors
            },
            'authentication_results': {
                'SPF': spf_result,
                'DKIM': dkim_result,
                'DMARC': dmarc_result
            },
            'attachments': attachments,
            'suspicious_html': suspicious_html,
            'suspicious_language': suspicious_language
        }

    def _is_suspicious_attachment(self, content_type, filename):
        """Check if attachment is suspicious"""
        suspicious_types = [
            'application/x-executable',
            'application/x-msdownload',
            'application/x-msdos-program',
            'application/x-msdos-windows',
            'application/x-msdos',
            'application/x-msdos-program',
            'application/x-msdos-windows',
            'application/x-msdos',
            'application/x-msdos-program',
            'application/x-msdos-windows'
        ]
        
        suspicious_extensions = [
            '.exe', '.bat', '.cmd', '.vbs', '.js',
            '.wsf', '.hta', '.scr', '.pif', '.reg'
        ]
        
        return (content_type in suspicious_types or
                any(filename.lower().endswith(ext) for ext in suspicious_extensions)) 