import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Any, Optional
import re
from datetime import datetime
import ipaddress
import logging
from backend.utils.exceptions import handle_service_error

logger = logging.getLogger(__name__)

class EmailForensics:
    def __init__(self):
        self.parser = BytesParser(policy=policy.default)
        
    def analyze_headers(self, eml_content: bytes) -> Dict[str, Any]:
        """Comprehensive email header analysis for forensics"""
        try:
            msg = self.parser.parsebytes(eml_content)
            
            # Extract sender IP from content
            sender_ip = self._extract_sender_ip_from_content(eml_content)
            
            analysis = {
                'message_id': self._extract_message_id(msg),
                'routing_path': self._analyze_routing_path(msg),
                'header_analysis': self._detailed_header_analysis(msg),
                'timeline': self._extract_timeline(msg),
                'sender_chain': self._analyze_sender_chain(msg),
                'authentication': self._analyze_authentication(msg),
                'forensic_indicators': self._identify_forensic_indicators(msg),
                'sender_ip': sender_ip
            }
            
            logger.info("Email forensics analysis completed")
            return analysis
            
        except Exception as e:
            logger.error(f"Service error in email_forensics_analysis: {type(e).__name__}")
            raise handle_service_error(e, "email_forensics_analysis")

    def _extract_message_id(self, msg) -> Optional[str]:
        """Extract and validate Message-ID"""
        message_id = msg.get('Message-ID', '')
        if message_id:
            # Clean up Message-ID format
            message_id = message_id.strip('<>')
            return message_id
        return None

    def _analyze_routing_path(self, msg) -> List[Dict[str, Any]]:
        """Analyze email routing path from Received headers"""
        routing_path = []
        received_headers = msg.get_all('Received', [])
        
        for i, header in enumerate(received_headers):
            hop = {
                'hop_number': len(received_headers) - i,
                'raw_header': header,
                'timestamp': self._extract_timestamp_from_received(header),
                'from_host': self._extract_from_host(header),
                'to_host': self._extract_to_host(header),
                'protocol': self._extract_protocol(header),
                'ip_addresses': self._extract_ip_addresses(header),
                'analysis': self._analyze_routing_hop(header, i, len(received_headers))
            }
            routing_path.append(hop)
        
        # Reverse to show chronological order
        routing_path.reverse()
        return routing_path

    def _extract_timestamp_from_received(self, header: str) -> Optional[str]:
        """Extract timestamp from Received header"""
        # Common timestamp patterns in Received headers
        patterns = [
            r';\s*(\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})',
            r';\s*(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})',
            r';\s*(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, header)
            if match:
                return match.group(1)
        return None

    def _extract_from_host(self, header: str) -> Optional[str]:
        """Extract 'from' host from Received header"""
        patterns = [
            r'from\s+([^\s]+)',
            r'from\s+([^\s]+)\s+\(([^)]+)\)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, header, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_to_host(self, header: str) -> Optional[str]:
        """Extract 'to' host from Received header"""
        patterns = [
            r'by\s+([^\s]+)',
            r'by\s+([^\s]+)\s+\(([^)]+)\)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, header, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_protocol(self, header: str) -> Optional[str]:
        """Extract protocol from Received header"""
        protocols = ['SMTP', 'ESMTP', 'HTTP', 'HTTPS', 'FTP']
        for protocol in protocols:
            if protocol in header.upper():
                return protocol
        return None

    def _extract_ip_addresses(self, header: str) -> List[str]:
        """Extract IP addresses from Received header"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, header)
        return ips

    def _extract_sender_ip_from_content(self, eml_content: bytes) -> Optional[str]:
        """Recursively extract the first public sender IP from all Received and Authentication-Results headers in all parts."""
        try:
            msg = self.parser.parsebytes(eml_content)

            # Recursively collect all relevant headers from all parts
            def collect_headers(msg):
                headers = []
                if hasattr(msg, 'walk'):
                    for part in msg.walk():
                        # Only process message/rfc822 or main parts
                        if part.get_content_type() == 'message/rfc822':
                            # Embedded message: parse as new message
                            payload = part.get_payload(decode=True)
                            if payload:
                                try:
                                    embedded_msg = self.parser.parsebytes(payload)
                                    headers.extend(collect_headers(embedded_msg))
                                except Exception as e:
                                    logger.warning(f"Failed to parse embedded message/rfc822: {e}")
                        else:
                            # Collect headers from this part
                            received = part.get_all('Received', []) or []
                            auth_results = part.get_all('Authentication-Results', []) or []
                            headers.extend([(h, 'Received') for h in received])
                            headers.extend([(h, 'Authentication-Results') for h in auth_results])
                else:
                    # Not multipart, just collect from this message
                    received = msg.get_all('Received', []) or []
                    auth_results = msg.get_all('Authentication-Results', []) or []
                    headers.extend([(h, 'Received') for h in received])
                    headers.extend([(h, 'Authentication-Results') for h in auth_results])
                return headers

            all_headers = collect_headers(msg)

            # Try to extract sender IP from Authentication-Results headers first
            for header, header_type in all_headers:
                if header_type == 'Authentication-Results':
                    sender_ip_match = re.search(r'sender IP is (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', header)
                    if sender_ip_match:
                        ip_str = sender_ip_match.group(1)
                        try:
                            ip_obj = ipaddress.ip_address(ip_str)
                            if ip_obj.is_global and not ip_obj.is_private:
                                logger.info(f"Extracted sender IP from Authentication-Results: {ip_str}")
                                return ip_str
                        except ValueError:
                            continue

            # Then try to extract from Received headers
            for header, header_type in all_headers:
                if header_type == 'Received':
                    # Try multiple IP extraction patterns
                    ip_candidates = []
                    bracket_matches = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
                    ip_candidates.extend(bracket_matches)
                    plain_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', header)
                    ip_candidates.extend(plain_matches)
                    for ip_str in ip_candidates:
                        try:
                            ip_obj = ipaddress.ip_address(ip_str)
                            if ip_obj.is_global and not ip_obj.is_private:
                                logger.info(f"Extracted sender IP from Received: {ip_str}")
                                return ip_str
                        except ValueError:
                            continue

            # Fallback: try to extract from body content (for embedded headers)
            body_content = self._get_email_body_content(msg)
            if body_content:
                embedded_auth_match = re.search(r'sender IP is (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body_content)
                if embedded_auth_match:
                    ip_str = embedded_auth_match.group(1)
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_global and not ip_obj.is_private:
                            logger.info(f"Extracted sender IP from embedded Authentication-Results: {ip_str}")
                            return ip_str
                    except ValueError:
                        pass
                embedded_ips = self._extract_ips_from_text(body_content)
                for ip in embedded_ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_global and not ip_obj.is_private:
                            logger.info(f"Extracted sender IP from embedded content: {ip}")
                            return ip
                    except ValueError:
                        continue

            logger.warning("No public sender IP found in any header.")
            return None
        except Exception as e:
            logger.error(f"Service error in extract_sender_ip: {type(e).__name__}")
            raise handle_service_error(e, "extract_sender_ip")

    def _extract_ips_from_text(self, text: str) -> List[str]:
        """Extract all IP addresses from text using multiple patterns."""
        ips = []
        
        # IPv4 patterns
        ipv4_patterns = [
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',  # Standard IPv4
            r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',  # IPv4 in brackets
        ]
        
        # IPv6 patterns
        ipv6_patterns = [
            r'\b([0-9a-fA-F:]+:[0-9a-fA-F:]+)\b',  # Standard IPv6
            r'\[([0-9a-fA-F:]+:[0-9a-fA-F:]+)\]',  # IPv6 in brackets
        ]
        
        for pattern in ipv4_patterns + ipv6_patterns:
            matches = re.findall(pattern, text)
            ips.extend(matches)
        
        return list(set(ips))  # Remove duplicates

    def _get_email_body_content(self, msg) -> Optional[str]:
        """Extract text content from email body for embedded header analysis."""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        return part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Service error in extract_email_body: {type(e).__name__}")
            raise handle_service_error(e, "extract_email_body")

    def _analyze_routing_hop(self, header: str, hop_index: int, total_hops: int) -> Dict[str, Any]:
        """Analyze individual routing hop for suspicious patterns"""
        analysis = {
            'suspicious': False,
            'indicators': [],
            'risk_score': 0
        }
        
        # Check for suspicious patterns
        if 'localhost' in header.lower():
            analysis['suspicious'] = True
            analysis['indicators'].append('Localhost routing detected')
            analysis['risk_score'] += 20
            
        if '127.0.0.1' in header:
            analysis['suspicious'] = True
            analysis['indicators'].append('Loopback IP detected')
            analysis['risk_score'] += 25
            
        if hop_index == 0 and total_hops < 3:
            analysis['indicators'].append('Insufficient routing hops')
            analysis['risk_score'] += 10
            
        # Check for private IP ranges
        ips = self._extract_ip_addresses(header)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    analysis['indicators'].append(f'Private IP detected: {ip}')
                    analysis['risk_score'] += 5
            except:
                pass
                
        return analysis

    def _detailed_header_analysis(self, msg) -> Dict[str, Any]:
        """Detailed analysis of all email headers"""
        analysis = {
            'basic_headers': {},
            'security_headers': {},
            'custom_headers': {},
            'header_count': 0
        }
        
        # Analyze all headers
        for header_name, header_value in msg.items():
            analysis['header_count'] += 1
            
            if header_name.lower() in ['from', 'to', 'cc', 'bcc', 'subject', 'date']:
                analysis['basic_headers'][header_name] = {
                    'value': header_value,
                    'analysis': self._analyze_basic_header(header_name, header_value)
                }
            elif header_name.lower() in ['received-spf', 'dkim-signature', 'dmarc-results', 'authentication-results']:
                analysis['security_headers'][header_name] = {
                    'value': header_value,
                    'analysis': self._analyze_security_header(header_name, header_value)
                }
            else:
                analysis['custom_headers'][header_name] = {
                    'value': header_value,
                    'analysis': self._analyze_custom_header(header_name, header_value)
                }
        
        return analysis

    def _analyze_basic_header(self, name: str, value: str) -> Dict[str, Any]:
        """Analyze basic email headers"""
        analysis = {
            'suspicious': False,
            'indicators': [],
            'risk_score': 0
        }
        
        if name.lower() == 'from':
            # Check for suspicious sender patterns
            if re.search(r'[0-9]{10,}', value):
                analysis['suspicious'] = True
                analysis['indicators'].append('Suspicious sender format')
                analysis['risk_score'] += 15
                
        elif name.lower() == 'subject':
            # Check for urgency indicators
            urgency_words = ['urgent', 'immediate', 'action required', 'account suspended']
            for word in urgency_words:
                if word.lower() in value.lower():
                    analysis['indicators'].append(f'Urgency indicator: {word}')
                    analysis['risk_score'] += 5
                    
        return analysis

    def _analyze_security_header(self, name: str, value: str) -> Dict[str, Any]:
        """Analyze security-related headers"""
        analysis = {
            'status': 'unknown',
            'details': value,
            'risk_score': 0
        }
        
        if name.lower() == 'received-spf':
            if 'pass' in value.lower():
                analysis['status'] = 'pass'
            elif 'fail' in value.lower():
                analysis['status'] = 'fail'
                analysis['risk_score'] += 25
            elif 'neutral' in value.lower():
                analysis['status'] = 'neutral'
                analysis['risk_score'] += 10
                
        elif name.lower() == 'dkim-signature':
            if value:
                analysis['status'] = 'present'
            else:
                analysis['status'] = 'missing'
                analysis['risk_score'] += 15
                
        return analysis

    def _analyze_custom_header(self, name: str, value: str) -> Dict[str, Any]:
        """Analyze custom headers for suspicious patterns"""
        analysis = {
            'suspicious': False,
            'indicators': [],
            'risk_score': 0
        }
        
        # Check for suspicious custom headers
        suspicious_patterns = [
            r'x-.*spam',
            r'x-.*virus',
            r'x-.*malware'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, name.lower()):
                analysis['suspicious'] = True
                analysis['indicators'].append(f'Suspicious header pattern: {name}')
                analysis['risk_score'] += 10
                
        return analysis

    def _extract_timeline(self, msg) -> List[Dict[str, Any]]:
        """Extract and analyze email timeline"""
        timeline = []
        
        # Extract timestamps from various headers
        headers_with_time = [
            ('Date', msg.get('Date')),
            ('Received', msg.get_all('Received', []))
        ]
        
        for header_name, header_value in headers_with_time:
            if isinstance(header_value, list):
                for value in header_value:
                    timestamp = self._extract_timestamp_from_received(value)
                    if timestamp:
                        timeline.append({
                            'header': header_name,
                            'timestamp': timestamp,
                            'raw_value': value
                        })
            elif header_value:
                timeline.append({
                    'header': header_name,
                    'timestamp': header_value,
                    'raw_value': header_value
                })
        
        return timeline

    def _analyze_sender_chain(self, msg) -> List[Dict[str, Any]]:
        """Analyze sender chain for spoofing indicators"""
        sender_chain = []
        
        # Extract sender information from various headers
        sender_headers = [
            ('From', msg.get('From')),
            ('Reply-To', msg.get('Reply-To')),
            ('Return-Path', msg.get('Return-Path')),
            ('Sender', msg.get('Sender'))
        ]
        
        for header_name, header_value in sender_headers:
            if header_value:
                sender_chain.append({
                    'header': header_name,
                    'value': header_value,
                    'analysis': self._analyze_sender_header(header_name, header_value)
                })
        
        return sender_chain

    def _analyze_sender_header(self, name: str, value: str) -> Dict[str, Any]:
        """Analyze individual sender header"""
        analysis = {
            'suspicious': False,
            'indicators': [],
            'risk_score': 0,
            'domain': None,
            'email': None
        }
        
        # Extract email and domain
        email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', value)
        if email_match:
            analysis['email'] = email_match.group(1)
            analysis['domain'] = email_match.group(1).split('@')[1]
            
            # Check for suspicious patterns
            if analysis['domain'] in ['example.com', 'test.com', 'localhost']:
                analysis['suspicious'] = True
                analysis['indicators'].append('Suspicious domain')
                analysis['risk_score'] += 20
                
        return analysis

    def _analyze_authentication(self, msg) -> Dict[str, Any]:
        """
        Analyze email authentication headers (SPF, DKIM, DMARC) with a focus on the
        consolidated Authentication-Results header.
        """
        results = {
            'spf': {'status': 'neutral', 'sender': None},
            'dkim': {'status': 'neutral', 'domain': None},
            'dmarc': {'status': 'neutral', 'domain': None},
            'summary': 'No definitive authentication results found.',
            'overall_score': 0,
            'indicators': []
        }

        auth_results_header = msg.get('Authentication-Results')
        if auth_results_header:
            # Prefer the consolidated header, as it's the most reliable summary
            results['summary'] = 'Processed Authentication-Results header.'

            # Parse SPF - handle Gmail format: spf=pass (google.com: domain of employee@google.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=employee@google.com
            spf_match = re.search(r'spf=(\w+)', auth_results_header)
            if spf_match:
                results['spf']['status'] = spf_match.group(1).lower()
                # Extract sender from smtp.mailfrom part
                sender_match = re.search(r'smtp\.mailfrom=([^\s;]+)', auth_results_header)
                if sender_match:
                    results['spf']['sender'] = sender_match.group(1).strip()

            # Parse DKIM - handle Gmail format: dkim=pass header.i=@google.com header.s=20230601 header.b=xyz
            dkim_match = re.search(r'dkim=(\w+)', auth_results_header)
            if dkim_match:
                results['dkim']['status'] = dkim_match.group(1).lower()
                # Extract domain from header.i part
                domain_match = re.search(r'header\.i=@([^\s;]+)', auth_results_header)
                if domain_match:
                    results['dkim']['domain'] = domain_match.group(1).strip()

            # Parse DMARC - handle Gmail format: dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=google.com
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results_header)
            if dmarc_match:
                results['dmarc']['status'] = dmarc_match.group(1).lower()
                # Extract domain from header.from part
                dmarc_domain_match = re.search(r'header\.from=([^\s;]+)', auth_results_header)
                if dmarc_domain_match:
                    results['dmarc']['domain'] = dmarc_domain_match.group(1).strip()
        else:
            # Fallback for older email formats
            results['summary'] = 'No Authentication-Results header found, performing fallback checks.'
            # Fallback SPF check
            spf_header = msg.get('Received-SPF', '')
            if 'pass' in spf_header.lower():
                results['spf']['status'] = 'pass'
            elif 'fail' in spf_header.lower():
                results['spf']['status'] = 'fail'

            # Fallback DKIM check
            if msg.get('DKIM-Signature'):
                # Basic check, real verification is complex and not done here
                results['dkim']['status'] = 'pass' # Assume present means pass for this basic check
            else:
                results['dkim']['status'] = 'none'

        # Scoring logic - only penalize actual failures, not neutral/missing
        if results['spf']['status'] == 'fail':
            results['overall_score'] += 30
            results['indicators'].append('SPF check failed.')
        if results['dkim']['status'] == 'fail':
            results['overall_score'] += 30
            results['indicators'].append('DKIM signature verification failed.')
        if results['dmarc']['status'] in ['fail', 'quarantine', 'reject']:
            results['overall_score'] += 40
            results['indicators'].append(f'DMARC policy is {results["dmarc"]["status"]}.')

        if not results['indicators']:
             results['indicators'].append('All authentication checks passed or were neutral.')

        return results

    def _identify_forensic_indicators(self, msg) -> List[Dict[str, Any]]:
        """Identify forensic indicators for incident response"""
        indicators = []
        
        # Check for common forensic indicators
        forensic_checks = [
            ('Message-ID missing', lambda: not msg.get('Message-ID'), 15),
            ('No Received headers', lambda: not msg.get_all('Received'), 20),
            ('Suspicious routing', lambda: self._check_suspicious_routing(msg), 25),
            ('Authentication failure', lambda: self._check_auth_failures(msg), 30),
            ('Header manipulation', lambda: self._check_header_manipulation(msg), 20)
        ]
        
        for description, check_func, risk_score in forensic_checks:
            if check_func():
                indicators.append({
                    'indicator': description,
                    'risk_score': risk_score,
                    'severity': 'high' if risk_score >= 25 else 'medium' if risk_score >= 15 else 'low'
                })
                
        # Check for insufficient routing hops (less than 2 is suspicious)
        if len(msg.get_all('Received', [])) < 2:
            indicators.append({
                'type': 'routing',
                'severity': 'low',
                'indicator': 'Insufficient routing hops',
                'risk_score': 10
            })
                
        return indicators

    def _check_suspicious_routing(self, msg) -> bool:
        """Check for suspicious routing patterns"""
        received_headers = msg.get_all('Received', [])
        for header in received_headers:
            if 'localhost' in header.lower() or '127.0.0.1' in header:
                return True
        return False

    def _check_auth_failures(self, msg) -> bool:
        """Check for authentication failures"""
        spf_header = msg.get('Received-SPF', '')
        return 'fail' in spf_header.lower()

    def _check_header_manipulation(self, msg) -> bool:
        """Check for header manipulation indicators"""
        # Check for missing essential headers
        essential_headers = ['From', 'Date']
        for header in essential_headers:
            if not msg.get(header):
                return True
        return False 