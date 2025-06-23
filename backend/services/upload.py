from fastapi import UploadFile
from backend.services.phishing_detector import PhishingDetector
from backend.services.email_forensics import EmailForensics
from backend.services.virustotal import virustotal_service
from backend.utils.exceptions import (
    FileProcessingError, AnalysisError, VirusTotalError, 
    ValidationError, handle_service_error
)
from backend.utils.logging_config import get_logger
import asyncio
import hashlib
from typing import Dict, Any, List
import re

logger = get_logger(__name__)

ALLOWED_EXTENSIONS = {"eml"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

class UploadService:
    def __init__(self):
        self.phishing_detector = PhishingDetector()
        self.email_forensics = EmailForensics()

    def _calculate_file_hashes(self, contents: bytes) -> Dict[str, str]:
        """Calculate multiple hash types for file integrity and security"""
        return {
            'md5': hashlib.md5(contents).hexdigest(),
            'sha1': hashlib.sha1(contents).hexdigest(),
            'sha256': hashlib.sha256(contents).hexdigest(),
            'sha512': hashlib.sha512(contents).hexdigest()
        }

    def _extract_sender_ip(self, forensics_analysis: Dict[str, Any]) -> str:
        """Extract sender IP from routing path"""
        routing_path = forensics_analysis.get('routing_path', [])
        if routing_path:
            # Get the first hop (original sender)
            first_hop = routing_path[0]
            ip_addresses = first_hop.get('ip_addresses', [])
            if ip_addresses:
                return ip_addresses[0]
        return None

    async def validate_upload(self, file: UploadFile) -> bytes:
        """Validate uploaded file with comprehensive error handling"""
        try:
            # Check file extension
            if not file.filename:
                raise ValidationError("No filename provided", field="filename")
                
            file_extension = file.filename.rsplit(".", 1)[1].lower() if "." in file.filename else ""
            if file_extension not in ALLOWED_EXTENSIONS:
                raise ValidationError(
                    f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", 
                    field="file_extension"
                )

            # Read and check file size
            contents = await file.read()
            if len(contents) > MAX_FILE_SIZE:
                raise FileProcessingError(
                    f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB",
                    file_info={"filename": file.filename, "size": len(contents)}
                )

            if len(contents) == 0:
                raise FileProcessingError("Empty file", file_info={"filename": file.filename})

            # Calculate file hashes for security and integrity
            file_hashes = self._calculate_file_hashes(contents)
            logger.info(
                "File hashes calculated",
                file_name=file.filename,
                file_size=len(contents),
                md5_hash=file_hashes['md5'][:16] + "...",
                sha256_hash=file_hashes['sha256'][:16] + "..."
            )

            # Reset file pointer for further processing
            file.file.seek(0)
            
            logger.info(
                "File validation successful",
                file_name=file.filename,
                file_size=len(contents)
            )
            return contents
            
        except (ValidationError, FileProcessingError):
            raise
        except Exception as e:
            logger.error(f"Service error in file_validation: {type(e).__name__}")
            raise handle_service_error(e, "file_validation", {"file_name": file.filename})

    async def scan_file(self, contents: bytes) -> Dict[str, Any]:
        """Scan file for phishing indicators and perform comprehensive analysis with VirusTotal"""
        try:
            start_time = asyncio.get_event_loop().time()
            logger.info("Starting comprehensive email analysis with VirusTotal integration", file_size=len(contents))
            
            # Calculate file hashes
            file_hashes = self._calculate_file_hashes(contents)
            
            # Run email forensics analysis in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            forensics_start = asyncio.get_event_loop().time()
            forensics_analysis = await loop.run_in_executor(
                None, self.email_forensics.analyze_headers, contents
            )
            forensics_time = asyncio.get_event_loop().time() - forensics_start
            logger.info("Email forensics completed", duration=forensics_time)
            
            # Extract sender IP from forensics analysis
            sender_ip = forensics_analysis.get('sender_ip', 'N/A')
            
            # Get VirusTotal IP reputation first
            vt_start = asyncio.get_event_loop().time()
            vt_results = await self._get_virustotal_results(file_hashes, sender_ip)
            vt_time = asyncio.get_event_loop().time() - vt_start
            logger.info("VirusTotal analysis completed", duration=vt_time, sender_ip=sender_ip)
            
            # Run phishing detection in thread pool to avoid blocking
            phishing_start = asyncio.get_event_loop().time()
            phishing_analysis = await loop.run_in_executor(
                None, self.phishing_detector.analyze_eml, contents, vt_results.get('ip_reputation')
            )
            phishing_time = asyncio.get_event_loop().time() - phishing_start
            logger.info("Phishing detection completed", duration=phishing_time)
            
            # Create unified report
            report_start = asyncio.get_event_loop().time()
            unified_report = self._create_unified_report(
                phishing_analysis, 
                forensics_analysis, 
                file_hashes, 
                vt_results,
                sender_ip,
                len(contents)
            )
            report_time = asyncio.get_event_loop().time() - report_start
            
            total_time = asyncio.get_event_loop().time() - start_time
            overall_risk_score = unified_report['risk_scoring']['overall_risk_score']
            
            logger.info(
                "Comprehensive analysis completed",
                total_duration=total_time,
                forensics_duration=forensics_time,
                virustotal_duration=vt_time,
                phishing_duration=phishing_time,
                report_duration=report_time,
                overall_risk_score=overall_risk_score,
                is_phishing=unified_report['risk_scoring']['is_phishing']
            )
            
            return {
                'report': unified_report,
                'message': 'File analyzed successfully',
                'performance': {
                    'total_time': total_time,
                    'forensics_time': forensics_time,
                    'virustotal_time': vt_time,
                    'phishing_time': phishing_time,
                    'report_time': report_time
                }
            }
            
        except Exception as e:
            logger.error(f"Service error in scan_file: {type(e).__name__}")
            raise handle_service_error(e, "scan_file", {"file_name": file.filename})

    async def _get_virustotal_results(self, file_hashes: Dict[str, str], sender_ip: str, phishing_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get comprehensive VirusTotal analysis results"""
        from .virustotal import virustotal_service
        
        vt_results = {}
        
        # Check sender IP reputation
        if sender_ip and sender_ip != 'N/A':
            logger.info(f"Checking VirusTotal IP reputation for: {sender_ip}")
            vt_results['ip_reputation'] = await virustotal_service.check_ip_reputation(sender_ip)
        else:
            vt_results['ip_reputation'] = {
                'available': False,
                'error': 'No sender IP found',
                'verdict': 'unknown',
                'score': 0,
                'link': None
            }
        
        # Check main email file hash
        logger.info(f"Checking VirusTotal file hash: {file_hashes['sha256'][:16]}...")
        vt_results['file_hash'] = await virustotal_service.check_file_hash(file_hashes['sha256'])
        
        # Get attachment details from phishing analysis
        attachment_details = []
        if phishing_analysis and 'attachment_analysis' in phishing_analysis:
            attachment_details = phishing_analysis['attachment_analysis'].get('attachment_details', [])
            logger.info(f"Found {len(attachment_details)} attachments in phishing analysis")
        
        # Analyze all attachments
        if attachment_details:
            logger.info(f"Analyzing {len(attachment_details)} attachments with VirusTotal")
            vt_results['attachments'] = await virustotal_service.analyze_attachments(attachment_details)
        else:
            logger.info("No attachments found for VirusTotal analysis")
            vt_results['attachments'] = []
        
        return vt_results

    def _create_unified_report(self, phishing_analysis: Dict[str, Any], forensics_analysis: Dict[str, Any], 
                              file_hashes: Dict[str, str], vt_results: Dict[str, Any], sender_ip: str, file_size: int = 0) -> Dict[str, Any]:
        """Create a unified SOC-style report combining all analysis results"""
        
        # Extract basic email information
        header_analysis = forensics_analysis.get('header_analysis', {})
        basic_headers = header_analysis.get('basic_headers', {})
        
        # Get email metadata
        from_header = basic_headers.get('From', {}).get('value', 'Unknown')
        to_header = basic_headers.get('To', {}).get('value', 'Unknown')
        subject_header = basic_headers.get('Subject', {}).get('value', 'Unknown')
        date_header = basic_headers.get('Date', {}).get('value', 'Unknown')
        
        # Get sender IP from forensics analysis
        sender_ip = forensics_analysis.get('sender_ip', 'N/A')
        
        # Calculate overall risk score
        overall_risk_score = self._calculate_overall_risk(phishing_analysis, forensics_analysis, vt_results)
        
        # Determine if email is phishing based on overall risk score (not just phishing detector)
        is_phishing = overall_risk_score >= 30  # Lowered threshold from 40 to 30
        
        # Create threat indicators
        threat_indicators = []
        
        # Add phishing indicators
        for indicator in phishing_analysis.get('indicators', []):
            threat_indicators.append({
                'type': 'phishing',
                'severity': 'medium',
                'description': indicator
            })
        
        # Add forensic indicators
        for indicator in forensics_analysis.get('forensic_indicators', []):
            threat_indicators.append({
                'type': 'forensic',
                'severity': indicator.get('severity', 'low'),
                'description': indicator.get('description', 'Unknown indicator')
            })
        
        # Add VirusTotal indicators
        if vt_results.get('ip_reputation', {}).get('verdict') in ['malicious', 'suspicious']:
            threat_indicators.append({
                'type': 'virustotal_ip',
                'severity': 'high' if vt_results['ip_reputation']['verdict'] == 'malicious' else 'medium',
                'description': f"Sender IP {sender_ip} flagged as {vt_results['ip_reputation']['verdict']}"
            })
        
        if vt_results.get('file_hash', {}).get('verdict') in ['malicious', 'suspicious']:
            threat_indicators.append({
                'type': 'virustotal_file',
                'severity': 'high' if vt_results['file_hash']['verdict'] == 'malicious' else 'medium',
                'description': f"Email file flagged as {vt_results['file_hash']['verdict']}"
            })
        
        # Add attachment indicators
        for attachment in vt_results.get('attachments', []):
            vt_result = attachment.get('virustotal', {})
            if vt_result.get('verdict') in ['malicious', 'suspicious']:
                threat_indicators.append({
                    'type': 'virustotal_attachment',
                    'severity': 'high' if vt_result['verdict'] == 'malicious' else 'medium',
                    'description': f"Attachment {attachment['filename']} flagged as {vt_result['verdict']}"
                })
        
        return {
            'metadata': {
                'from': from_header,
                'to': to_header,
                'subject': subject_header,
                'date': date_header,
                'message_id': forensics_analysis.get('message_id'),
                'sender_ip': sender_ip
            },
            'header_summary': {
                'total_headers': header_analysis.get('header_count', 0),
                'security_headers': len(header_analysis.get('security_headers', {})),
                'custom_headers': len(header_analysis.get('custom_headers', {}))
            },
            'delivery_chain': {
                'routing_hops': len(forensics_analysis.get('routing_path', [])),
                'routing_path': self._enhance_routing_path(forensics_analysis.get('routing_path', []), sender_ip),
                'timeline': forensics_analysis.get('timeline', [])
            },
            'threat_indicators': threat_indicators,
            'risk_scoring': {
                'phishing_score': phishing_analysis.get('score', 0),
                'overall_risk_score': overall_risk_score,
                'risk_level': self._get_risk_level(overall_risk_score),
                'is_phishing': is_phishing  # Now based on overall risk score
            },
            'virustotal_summary': {
                'ip_reputation': vt_results.get('ip_reputation', {}),
                'file_hash': vt_results.get('file_hash', {}),
                'attachments_analyzed': len(vt_results.get('attachments', [])),
                'malicious_attachments': len([a for a in vt_results.get('attachments', []) 
                                           if a.get('virustotal', {}).get('verdict') == 'malicious']),
                'suspicious_attachments': len([a for a in vt_results.get('attachments', []) 
                                             if a.get('virustotal', {}).get('verdict') == 'suspicious'])
            },
            'attachments': vt_results.get('attachments', []),
            'file_integrity': {
                'hashes': file_hashes,
                'file_size': file_size,
                'hash_verification': 'verified'
            },
            'detailed_analysis': {
                'phishing_analysis': phishing_analysis,
                'forensics_analysis': forensics_analysis
            },
            'analysis_timestamp': asyncio.get_event_loop().time()
        }

    def _calculate_overall_risk(self, phishing_analysis: Dict[str, Any], forensics_analysis: Dict[str, Any], 
                               vt_results: Dict[str, Any]) -> int:
        """Calculate overall risk score combining all analysis results with enhanced threat weighting"""
        overall_score = 0
        
        # Add phishing score (25% weight) - Reduced from 30%
        overall_score += phishing_analysis.get('score', 0) * 0.25
        
        # Add forensic indicators (5% weight) - Reduced from 10%
        forensic_indicators = forensics_analysis.get('forensic_indicators', [])
        forensic_score = sum(indicator.get('risk_score', 0) for indicator in forensic_indicators)
        overall_score += forensic_score * 0.05
        
        # Add authentication failures (5% weight) - Reduced from 10%
        auth_analysis = forensics_analysis.get('authentication', {})
        overall_score += auth_analysis.get('overall_score', 0) * 0.05
        
        # Add VirusTotal IP reputation (25% weight) - INCREASED from 15% - CRITICAL FACTOR
        ip_reputation = vt_results.get('ip_reputation', {})
        if ip_reputation.get('verdict') == 'malicious':
            overall_score += 80 * 0.25  # INCREASED from 50 - Malicious IP is critical
        elif ip_reputation.get('verdict') == 'suspicious':
            overall_score += 50 * 0.25  # INCREASED from 30
        elif not ip_reputation.get('available', False):
            # If IP analysis unavailable, check if we have a sender IP but no VT data
            sender_ip = forensics_analysis.get('sender_ip', 'N/A')
            if sender_ip and sender_ip != 'N/A':
                overall_score += 10 * 0.25  # Small penalty for unavailable VT data
        
        # Add VirusTotal file hash (20% weight) - HIGH PRIORITY
        file_hash = vt_results.get('file_hash', {})
        if file_hash.get('verdict') == 'malicious':
            overall_score += 70 * 0.2  # INCREASED from 50
        elif file_hash.get('verdict') == 'suspicious':
            overall_score += 40 * 0.2  # INCREASED from 30
        
        # Add attachment analysis (20% weight) - INCREASED from 15% - CRITICAL FACTOR
        attachments = vt_results.get('attachments', [])
        attachment_score = 0
        
        # Check for dangerous attachments even without VirusTotal data
        attachment_analysis = phishing_analysis.get('attachment_analysis', {})
        attachment_details = attachment_analysis.get('attachment_details', [])
        
        for attachment in attachment_details:
            # High-risk attachment patterns
            if attachment.get('suspicious', False):
                risk_score = attachment.get('risk_score', 0)
                if risk_score >= 35:  # Dangerous double extension
                    attachment_score += 60  # INCREASED from 50
                elif risk_score >= 15:  # Archive files
                    attachment_score += 40  # INCREASED from 30
                else:  # Other suspicious
                    attachment_score += 25  # INCREASED from 15
        
        # Add VirusTotal attachment analysis if available
        for attachment in attachments:
            vt_result = attachment.get('virustotal', {})
            if vt_result.get('verdict') == 'malicious':
                attachment_score += 70  # INCREASED from 50
            elif vt_result.get('verdict') == 'suspicious':
                attachment_score += 50  # INCREASED from 30
            attachment_score += attachment.get('risk_score', 0)
        
        overall_score += attachment_score * 0.2  # INCREASED weight from 0.15
        
        # Cap at 100
        return min(int(overall_score), 100)

    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'very_low'

    def _enhance_routing_path(self, routing_path: List[Dict[str, Any]], sender_ip: str) -> List[Dict[str, Any]]:
        """Enhance routing path by including sender IP when available"""
        if not sender_ip or sender_ip == 'N/A':
            return routing_path
            
        enhanced_path = []
        for hop in routing_path:
            hop_copy = hop.copy()
            # Add sender IP to the first hop if no IPs are present
            if not hop_copy.get('ip_addresses'):
                hop_copy['ip_addresses'] = [sender_ip]
            elif sender_ip not in hop_copy['ip_addresses']:
                hop_copy['ip_addresses'].append(sender_ip)
            enhanced_path.append(hop_copy)
        return enhanced_path

# Global instance
upload_service = UploadService() 