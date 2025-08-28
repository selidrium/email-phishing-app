import re
import email
from email import policy
from urllib.parse import urlparse
import hashlib
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self):
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'v.gd',
            'ow.ly', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to'
        ]
        
        self.suspicious_keywords_in_domains = [
            'badactor', 'malicious', 'phish', 'fake', 'scam', 'hack',
            'steal', 'virus', 'malware', 'trojan', 'spam', 'evil',
            'suspicious', 'dangerous', 'fraud', 'cheat', 'stealer'
        ]
        
        self.urgency_keywords = [
            'urgent', 'immediate', 'action required', 'account suspended',
            'verify now', 'confirm immediately', 'security alert',
            'unauthorized access', 'account locked', 'payment overdue',
            'suspended', 'blocked', 'restricted', 'expired', 'critical'
        ]
        
        self.suspicious_keywords = [
            'bank transfer', 'wire transfer', 'gift card', 'bitcoin',
            'cryptocurrency', 'lottery', 'inheritance', 'prize',
            'free money', 'urgent help needed', 'verify credentials',
            'login', 'password', 'account', 'security', 'verify',
            # Old English/Archaic words commonly used in phishing
            'hath', 'doth', 'thou', 'thee', 'thy', 'thine', 'ye', 'verily',
            'forsooth', 'prithee', 'alas', 'behold', 'lo', 'nay', 'aye',
            'wherefore', 'henceforth', 'thereupon', 'whereas', 'whilst',
            'ere', 'erewhile', 'hither', 'thither', 'whither', 'yonder',
            'betwixt', 'amongst', 'whilst', 'amidst', 'towards', 'backwards',
            'forwards', 'upwards', 'downwards', 'inwards', 'outwards',
            'hereby', 'herein', 'hereof', 'hereto', 'herewith', 'thereby',
            'therein', 'thereof', 'thereto', 'therewith', 'whereby', 'wherein',
            'whereof', 'whereto', 'wherewith', 'hereafter', 'thereafter',
            'whereafter', 'herebefore', 'therebefore', 'wherebefore',
            'hereabouts', 'thereabouts', 'whereabouts', 'hereunto', 'thereunto',
            'whereunto', 'hereupon', 'thereupon', 'whereupon', 'hereinbefore',
            'thereinbefore', 'whereinbefore', 'hereinafter', 'thereinafter',
            'whereinafter', 'hereby', 'thereby', 'whereby', 'heretofore',
            'theretofore', 'wheretofore', 'herewithal', 'therewithal',
            'wherewithal', 'hereinabove', 'thereinabove', 'whereinabove',
            'hereinbelow', 'thereinbelow', 'whereinbelow', 'hereto',
            'thereto', 'whereto', 'herefrom', 'therefrom', 'wherefrom',
            'hereby', 'thereby', 'whereby', 'herein', 'therein', 'wherein',
            'hereof', 'thereof', 'whereof', 'hereon', 'thereon', 'whereon',
            'hereunder', 'thereunder', 'whereunder', 'herewith', 'therewith',
            'wherewith', 'herewithout', 'therewithout', 'wherewithout',
            # Common phishing politeness and urgency words
            'kindly', 'please', 'sir', 'madam', 'dear', 'esteemed', 'honorable',
            'respectfully', 'urgently', 'immediately', 'asap', 'right away',
            'without delay', 'promptly', 'expeditiously', 'forthwith',
            'posthaste', 'straightaway', 'instantly', 'momentarily',
            'presently', 'shortly', 'directly', 'forthcoming', 'upcoming',
            'pending', 'awaiting', 'expecting', 'anticipating', 'preparing',
            'arranging', 'organizing', 'coordinating', 'facilitating',
            'enabling', 'assisting', 'supporting', 'helping', 'guiding',
            'advising', 'informing', 'notifying', 'updating', 'confirming',
            'verifying', 'validating', 'authenticating', 'authorizing',
            'approving', 'endorsing', 'recommending', 'suggesting',
            'proposing', 'requesting', 'asking', 'seeking', 'requiring',
            'needing', 'wanting', 'desiring', 'hoping', 'wishing',
            'trusting', 'believing', 'thinking', 'feeling', 'knowing',
            'understanding', 'realizing', 'recognizing', 'acknowledging',
            'appreciating', 'thanking', 'grateful', 'blessed', 'fortunate',
            'lucky', 'privileged', 'honored', 'proud', 'happy', 'glad',
            'pleased', 'satisfied', 'content', 'comfortable', 'secure',
            'safe', 'protected', 'guarded', 'watched', 'monitored',
            'tracked', 'traced', 'followed', 'pursued', 'chased',
            'hunted', 'sought', 'found', 'discovered', 'uncovered',
            'revealed', 'exposed', 'shown', 'displayed', 'presented',
            'offered', 'provided', 'supplied', 'delivered', 'sent',
            'forwarded', 'transferred', 'moved', 'shifted', 'changed',
            'altered', 'modified', 'adjusted', 'updated', 'upgraded',
            'improved', 'enhanced', 'strengthened', 'fortified', 'secured'
        ]

    def analyze_eml(self, eml_content: bytes, ip_analysis: Dict = None) -> Dict:
        """Analyze .eml file for phishing indicators with IP analysis integration"""
        try:
            logger.info(f"Starting phishing analysis of email ({len(eml_content)} bytes)")
            
            # Parse email
            msg = email.message_from_bytes(eml_content, policy=policy.default)
            
            sender_analysis = self._analyze_sender(msg)
            content_analysis = self._analyze_content(msg)
            url_analysis = self._analyze_urls(msg)
            header_analysis = self._analyze_headers(msg)
            attachment_analysis = self._analyze_attachments(msg)
            ip_analysis_result = self._analyze_ip_reputation(ip_analysis) if ip_analysis else {'score': 0, 'indicators': []}
            
            logger.info(f"Individual analysis results:")
            logger.info(f"  Sender: score={sender_analysis.get('score', 0)}, indicators={sender_analysis.get('indicators', [])}")
            logger.info(f"  Content: score={content_analysis.get('score', 0)}, indicators={content_analysis.get('indicators', [])}")
            logger.info(f"  URLs: score={url_analysis.get('score', 0)}, indicators={url_analysis.get('indicators', [])}")
            logger.info(f"  Headers: score={header_analysis.get('score', 0)}, indicators={header_analysis.get('indicators', [])}")
            logger.info(f"  Attachments: score={attachment_analysis.get('score', 0)}, indicators={attachment_analysis.get('indicators', [])}")
            logger.info(f"  IP Analysis: score={ip_analysis_result.get('score', 0)}, indicators={ip_analysis_result.get('indicators', [])}")
            
            analysis = {
                'score': 0,
                'indicators': [],
                'risk_level': 'low',
                'sender_analysis': sender_analysis,
                'content_analysis': content_analysis,
                'url_analysis': url_analysis,
                'header_analysis': header_analysis,
                'attachment_analysis': attachment_analysis,
                'ip_analysis': ip_analysis_result
            }
            
            # Aggregate all indicators
            all_indicators = (
                sender_analysis.get('indicators', []) +
                content_analysis.get('indicators', []) +
                url_analysis.get('indicators', []) +
                header_analysis.get('indicators', []) +
                attachment_analysis.get('indicators', []) +
                ip_analysis_result.get('indicators', [])
            )
            
            analysis['indicators'] = all_indicators
            logger.info(f"Aggregated indicators: {all_indicators}")
            
            # Calculate overall score
            analysis['score'] = self._calculate_score(analysis)
            analysis['risk_level'] = self._get_risk_level(analysis['score'])
            analysis['is_phishing'] = analysis['score'] >= 30  # Lowered threshold for better detection
            
            logger.info(f"Phishing analysis completed. Score: {analysis['score']}, Risk: {analysis['risk_level']}, Indicators count: {len(all_indicators)}")
            return analysis
            
        except Exception as e:
            logger.error(f"Service error in analyze_email: {type(e).__name__}")
            raise handle_service_error(e, "analyze_email")

    def _analyze_sender(self, msg) -> Dict:
        """Analyze sender information for spoofing indicators"""
        indicators = []
        score = 0
        
        # Check From header
        from_header = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        
        # Check for suspicious sender patterns
        if re.search(r'[0-9]{10,}', from_header):
            indicators.append('Suspicious sender format')
            score += 10
            
        # Check for suspicious keywords in sender domain
        if any(keyword in from_header.lower() for keyword in self.suspicious_keywords_in_domains):
            indicators.append('Suspicious sender domain')
            score += 15
            
        # Check for mismatched Reply-To
        if reply_to and reply_to != from_header:
            indicators.append('Reply-To differs from From')
            score += 15
            
        # Check for generic sender names
        generic_names = ['support', 'admin', 'noreply', 'info', 'service']
        if any(name in from_header.lower() for name in generic_names):
            indicators.append('Generic sender name')
            score += 5
            
        return {'score': score, 'indicators': indicators, 'from': from_header, 'reply_to': reply_to}

    def _analyze_content(self, msg) -> Dict:
        """Analyze email content for suspicious patterns"""
        indicators = []
        score = 0
        
        # Get text content
        text_content = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                text_content += part.get_content()
            elif part.get_content_type() == "text/html":
                # Basic HTML to text conversion
                html_content = part.get_content()
                text_content += re.sub(r'<[^>]+>', '', html_content)
        
        text_lower = text_content.lower()
        
        # Check for urgency indicators
        urgency_count = sum(1 for keyword in self.urgency_keywords if keyword in text_lower)
        if urgency_count > 0:
            indicators.append(f'Urgency indicators found ({urgency_count})')
            score += urgency_count * 8
            
        # Check for suspicious keywords
        suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
        if suspicious_count > 0:
            indicators.append(f'Suspicious keywords found ({suspicious_count})')
            score += suspicious_count * 10
            
        # Check for poor grammar/spelling (basic check)
        if len(re.findall(r'\b\w{15,}\b', text_content)) > 5:
            indicators.append('Poor grammar/spelling detected')
            score += 10
            
        # Check for excessive use of exclamation marks
        if text_content.count('!') > 3:
            indicators.append('Excessive exclamation marks')
            score += 5
            
        return {'score': score, 'indicators': indicators, 'content_length': len(text_content)}

    def _analyze_urls(self, msg) -> Dict:
        """Analyze URLs in email for suspicious patterns"""
        indicators = []
        score = 0
        urls = []
        
        logger.info("Starting URL analysis")
        
        # Extract URLs from text content
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                content = part.get_content()
                logger.info(f"Analyzing content type: {part.get_content_type()}")
                logger.info(f"Content length: {len(content)}")
                logger.info(f"Content preview: {repr(content[:200])}")
                
                # Find URLs
                url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
                found_urls = re.findall(url_pattern, content)
                logger.info(f"Found URLs in this part: {found_urls}")
                urls.extend(found_urls)
        
        logger.info(f"Total URLs found: {urls}")
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                logger.info(f"Analyzing URL: {url}, Domain: {domain}")
                
                # Check for URL shorteners
                if any(shortener in domain for shortener in self.suspicious_domains):
                    indicators.append(f'URL shortener detected: {domain}')
                    score += 15
                    logger.info(f"URL shortener detected: {domain}")
                    
                # Check for suspicious keywords in domain names
                if any(keyword in domain for keyword in self.suspicious_keywords_in_domains):
                    indicators.append(f'Suspicious domain name: {domain}')
                    score += 20
                    logger.info(f"Suspicious domain detected: {domain}")
                    
                # Check for IP addresses in URLs
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    indicators.append(f'IP address in URL: {domain}')
                    score += 20
                    logger.info(f"IP address in URL: {domain}")
                    
                # Check for suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
                if any(tld in domain for tld in suspicious_tlds):
                    indicators.append(f'Suspicious TLD: {domain}')
                    score += 10
                    logger.info(f"Suspicious TLD: {domain}")
                    
                # Check for domains with many subdomains (potential evasion)
                if domain.count('.') > 2:
                    indicators.append(f'Excessive subdomains: {domain}')
                    score += 8
                    logger.info(f"Excessive subdomains: {domain}")
                    
            except Exception as e:
                indicators.append(f'Invalid URL format: {url}')
                score += 5
                logger.error(f"Error analyzing URL {url}: {e}")
        
        logger.info(f"URL analysis complete. Score: {score}, Indicators: {indicators}")
        return {'score': score, 'indicators': indicators, 'url_count': len(urls), 'urls': urls}

    def _analyze_headers(self, msg) -> Dict:
        """Analyze email headers for spoofing indicators"""
        indicators = []
        score = 0
        
        # Check Authentication-Results header (preferred method)
        auth_results = msg.get('Authentication-Results', '')
        
        if auth_results:
            # Parse the consolidated authentication header
            if 'spf=fail' in auth_results.lower():
                indicators.append('SPF check failed')
                score += 30
            if 'dkim=fail' in auth_results.lower():
                indicators.append('DKIM signature verification failed')
                score += 20
            if 'dmarc=fail' in auth_results.lower():
                indicators.append('DMARC check failed')
                score += 25
        else:
            # Fallback to individual headers for older email formats
            spf = msg.get('Received-SPF', '')
            dkim = msg.get('DKIM-Signature', '')
            
            if 'fail' in spf.lower():
                indicators.append('SPF check failed')
                score += 30
                
            if not dkim:
                indicators.append('No DKIM signature')
                score += 20
                
            # Only penalize for missing authentication if both methods fail
            if not spf and not dkim and not auth_results:
                indicators.append('No authentication headers found')
                score += 15
            
        # Check for insufficient routing hops (less than 2 is suspicious)
        received_headers = msg.get_all('Received', [])
        if len(received_headers) < 2:
            indicators.append('Insufficient Received headers')
            score += 10
            
        # Check for suspicious routing
        for header in received_headers:
            if 'localhost' in header.lower() or '127.0.0.1' in header:
                indicators.append('Suspicious routing detected')
                score += 15
                
        return {'score': score, 'indicators': indicators, 'auth_results': bool(auth_results)}

    def _analyze_attachments(self, msg) -> Dict:
        """Analyze email attachments for suspicious files and extract hashes"""
        indicators = []
        score = 0
        attachments = []
        attachment_details = []
        
        for part in msg.walk():
            if part.get_filename():
                filename = part.get_filename().lower()
                attachments.append(filename)
                
                # Extract attachment details for VirusTotal analysis
                attachment_info = {
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0,
                    'hash_sha256': None,
                    'suspicious': False,
                    'risk_score': 0
                }
                
                # Calculate hash for VirusTotal analysis
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        attachment_info['hash_sha256'] = hashlib.sha256(payload).hexdigest()
                except Exception as e:
                    logger.warning(f"Could not calculate hash for attachment {filename}: {e}")
                
                # Check for executable files (HIGH RISK)
                exe_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar', '.msi']
                if any(filename.endswith(ext) for ext in exe_extensions):
                    indicators.append(f'Executable attachment: {filename}')
                    score += 40  # Increased from 30
                    attachment_info['suspicious'] = True
                    attachment_info['risk_score'] += 40
                    
                # Check for double extensions (HIGH RISK - malware hiding technique)
                if filename.count('.') > 1:
                    # Check for specific dangerous patterns
                    dangerous_patterns = [
                        '.pdf.exe', '.doc.exe', '.xls.exe', '.ppt.exe',
                        '.pdf.bat', '.doc.bat', '.xls.bat',
                        '.pdf.cmd', '.doc.cmd', '.xls.cmd',
                        '.pdf.scr', '.doc.scr', '.xls.scr',
                        '.pdf.arj', '.doc.arj', '.xls.arj',  # Archive files hiding executables
                        '.pdf.rar', '.doc.rar', '.xls.rar',
                        '.pdf.zip', '.doc.zip', '.xls.zip'
                    ]
                    
                    if any(pattern in filename for pattern in dangerous_patterns):
                        indicators.append(f'Dangerous double extension: {filename}')
                        score += 35  # High score for dangerous patterns
                        attachment_info['suspicious'] = True
                        attachment_info['risk_score'] += 35
                    else:
                        indicators.append(f'Double extension: {filename}')
                        score += 25  # Increased from 15
                        attachment_info['suspicious'] = True
                        attachment_info['risk_score'] += 25
                    
                # Check for archive files (MEDIUM RISK - often used to hide malware)
                archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.arj', '.ace']
                if any(filename.endswith(ext) for ext in archive_extensions):
                    indicators.append(f'Archive attachment: {filename}')
                    score += 15
                    attachment_info['suspicious'] = True
                    attachment_info['risk_score'] += 15
                    
                # Check for suspicious names (LOW RISK)
                suspicious_names = ['invoice', 'document', 'scan', 'receipt', 'statement', 'order', 'nueva orden']
                if any(name in filename for name in suspicious_names):
                    indicators.append(f'Suspicious filename: {filename}')
                    score += 8  # Increased from 5
                    attachment_info['suspicious'] = True
                    attachment_info['risk_score'] += 8
                
                attachment_details.append(attachment_info)
                    
        return {
            'score': score, 
            'indicators': indicators, 
            'attachment_count': len(attachments), 
            'attachments': attachments,
            'attachment_details': attachment_details
        }

    def _analyze_ip_reputation(self, ip_analysis: Dict) -> Dict:
        """Analyze IP reputation data for phishing indicators"""
        indicators = []
        score = 0
        
        if not ip_analysis or not ip_analysis.get('available', False):
            indicators.append('IP reputation data unavailable')
            score += 5
            return {'score': score, 'indicators': indicators}
        
        # Check VirusTotal verdict
        verdict = ip_analysis.get('verdict', 'unknown')
        if verdict == 'malicious':
            indicators.append('IP flagged as malicious by VirusTotal')
            score += 50  # High weight for malicious IP
        elif verdict == 'suspicious':
            indicators.append('IP flagged as suspicious by VirusTotal')
            score += 30  # Medium weight for suspicious IP
        
        # Check reputation score (VirusTotal's own system)
        reputation = ip_analysis.get('reputation', 0)
        if reputation < -50:
            indicators.append(f'IP has poor reputation score: {reputation}')
            score += 25
        elif reputation < 0:
            indicators.append(f'IP has negative reputation score: {reputation}')
            score += 15
        
        # Check for specific threat categories
        threat_categories = ip_analysis.get('threat_categories', [])
        if threat_categories:
            indicators.append(f'IP associated with threats: {", ".join(threat_categories[:3])}')
            score += len(threat_categories) * 10
        
        # Check for suspicious tags
        tags = ip_analysis.get('tags', [])
        suspicious_tags = ['tor_exit_node', 'vpn_provider', 'malware', 'phishing', 'spam']
        for tag in tags:
            if tag in suspicious_tags:
                indicators.append(f'IP tagged as: {tag}')
                score += 15
        
        # Check for high-risk countries (optional - can be customized)
        high_risk_countries = ['XX']  # Add specific country codes if needed
        country = ip_analysis.get('country', 'Unknown')
        if country in high_risk_countries:
            indicators.append(f'IP from high-risk country: {country}')
            score += 10
        
        # Check ASN information
        as_owner = ip_analysis.get('as_owner', 'Unknown')
        if 'vpn' in as_owner.lower() or 'proxy' in as_owner.lower():
            indicators.append(f'IP from VPN/Proxy provider: {as_owner}')
            score += 20
        
        return {'score': score, 'indicators': indicators}

    def _calculate_score(self, analysis: Dict) -> int:
        """Calculate overall phishing score with IP analysis as core factor"""
        total_score = 0
        
        # Weight different analysis components (IP analysis gets highest weight)
        # IP Analysis gets highest weight due to being a core factor
        total_score += analysis['ip_analysis']['score'] * 0.40  # Highest weight for IP reputation
        # Attachments get high weight due to high risk
        total_score += analysis['attachment_analysis']['score'] * 0.25  # Decreased from 0.35
        # Headers get medium weight due to authentication importance
        total_score += analysis['header_analysis']['score'] * 0.15  # Decreased from 0.25
        # URLs get medium weight
        total_score += analysis['url_analysis']['score'] * 0.10  # Decreased from 0.20
        # Content gets lower weight
        total_score += analysis['content_analysis']['score'] * 0.07  # Decreased from 0.15
        # Sender gets lowest weight
        total_score += analysis['sender_analysis']['score'] * 0.03  # Decreased from 0.05
        
        return min(100, int(total_score))

    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level with adjusted thresholds"""
        if score >= 60:  # Lowered from 75
            return 'high'
        elif score >= 40:  # Lowered from 50
            return 'medium'
        elif score >= 20:  # Lowered from 25
            return 'low'
        else:
            return 'very_low' 
