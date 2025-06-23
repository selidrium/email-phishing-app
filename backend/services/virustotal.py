import aiohttp
import asyncio
import os
import logging
from typing import Dict, List, Optional, Any
import json
import ipaddress
from backend.utils.exceptions import VirusTotalError, ValidationError
from backend.utils.logging_config import get_logger
from backend.utils.exceptions import handle_service_error

logger = get_logger(__name__)

class VirusTotalService:
    def __init__(self):
        self.api_key = None
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = None
        
        # Whitelist of known legitimate IP ranges to prevent false positives
        self.legitimate_ip_ranges = [
            # Google's IP ranges
            "8.8.8.0/24",      # Google DNS
            "8.8.4.0/24",      # Google DNS
            "209.85.128.0/17", # Google Mail servers
            "66.102.0.0/20",   # Google
            "72.14.192.0/18",  # Google
            "74.125.0.0/16",   # Google
            "108.177.8.0/21",  # Google
            "173.194.0.0/16",  # Google
            "207.126.144.0/20", # Google
            "209.85.128.0/17", # Google
            "216.58.192.0/19", # Google
            "216.239.32.0/19", # Google
            # Microsoft's IP ranges
            "13.64.0.0/11",    # Microsoft
            "13.104.0.0/14",   # Microsoft
            "20.36.0.0/14",    # Microsoft
            "20.40.0.0/13",    # Microsoft
            "20.48.0.0/12",    # Microsoft
            "20.64.0.0/10",    # Microsoft
            "40.64.0.0/10",    # Microsoft
            "52.224.0.0/11",   # Microsoft
            "104.208.0.0/13",  # Microsoft
            # Other major email providers
            "17.0.0.0/8",      # Apple
            "142.250.0.0/15",  # Google
        ]
        
        # Compile the IP ranges for efficient checking
        self.legitimate_networks = [ipaddress.ip_network(range_str) for range_str in self.legitimate_ip_ranges]
        
    def configure(self, api_key: str):
        """Configure the service with API key"""
        if not api_key:
            raise ValidationError("VirusTotal API key is required", field="api_key")
        self.api_key = api_key
        logger.info("VirusTotal service configured successfully")
    
    async def _get_session(self):
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            headers = {
                "x-apikey": self.api_key,
                "User-Agent": "PhishingDetectionApp/1.0"
            }
            self.session = aiohttp.ClientSession(headers=headers)
        return self.session
    
    async def close_session(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    def _is_legitimate_ip(self, ip_address: str) -> bool:
        """Check if IP is in legitimate whitelist"""
        try:
            ip = ipaddress.ip_address(ip_address)
            for network in self.legitimate_networks:
                if ip in ipaddress.ip_network(network):
                    return True
            return any(ip in network for network in self.legitimate_networks)
        except ValueError:
            return False
    
    async def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation on VirusTotal with comprehensive analysis"""
        if not self.api_key:
            raise VirusTotalError("VirusTotal API key not configured", vt_operation="ip_reputation")
        
        # Check if IP is in legitimate whitelist
        if self._is_legitimate_ip(ip_address):
            logger.info("IP is in legitimate whitelist, skipping VirusTotal check", ip_address=ip_address)
            return {
                'available': True,
                'verdict': 'clean',
                'score': 0,
                'link': f"https://www.virustotal.com/gui/ip-address/{ip_address}/detection",
                'malicious_count': 0,
                'suspicious_count': 0,
                'total_count': 0,
                'country': 'Unknown',
                'as_owner': 'Legitimate Provider',
                'whitelisted': True,
                'threat_categories': [],
                'reputation': 0,
                'tags': ['legitimate_provider']
            }
        
        try:
            session = await self._get_session()
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            
            logger.info("Checking VirusTotal IP reputation", ip_address=ip_address)
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    # Extract reputation data
                    last_analysis_stats = attributes.get('last_analysis_stats', {})
                    malicious_count = last_analysis_stats.get('malicious', 0)
                    suspicious_count = last_analysis_stats.get('suspicious', 0)
                    total_count = sum(last_analysis_stats.values())
                    
                    # Calculate score (0-100, higher = more malicious)
                    if total_count > 0:
                        score = int((malicious_count + suspicious_count) / total_count * 100)
                    else:
                        score = 0
                    
                    # Determine verdict
                    if malicious_count > 0:
                        verdict = 'malicious'
                    elif suspicious_count > 0:
                        verdict = 'suspicious'
                    elif total_count > 0:
                        verdict = 'clean'
                    else:
                        verdict = 'unknown'
                    
                    # Extract additional threat intelligence
                    threat_categories = []
                    tags = attributes.get('tags', [])
                    
                    # Check for specific threat categories
                    if attributes.get('last_analysis_results'):
                        for engine, result in attributes['last_analysis_results'].items():
                            if result.get('category') == 'malicious':
                                threat_categories.append(f"{engine}: {result.get('result', 'malicious')}")
                    
                    # Get reputation score (VirusTotal's own reputation system)
                    reputation = attributes.get('reputation', 0)
                    
                    # Extract geolocation and network info
                    country = attributes.get('country', 'Unknown')
                    as_owner = attributes.get('as_owner', 'Unknown')
                    asn = attributes.get('asn', 'Unknown')
                    
                    # Add network-related tags
                    if as_owner and 'cloud' in as_owner.lower():
                        tags.append('cloud_provider')
                    if as_owner and 'vpn' in as_owner.lower():
                        tags.append('vpn_provider')
                    if as_owner and 'tor' in as_owner.lower():
                        tags.append('tor_exit_node')
                    
                    return {
                        'available': True,
                        'verdict': verdict,
                        'score': score,
                        'link': f"https://www.virustotal.com/gui/ip-address/{ip_address}/detection",
                        'malicious_count': malicious_count,
                        'suspicious_count': suspicious_count,
                        'total_count': total_count,
                        'country': country,
                        'as_owner': as_owner,
                        'asn': asn,
                        'whitelisted': False,
                        'threat_categories': threat_categories,
                        'reputation': reputation,
                        'tags': tags,
                        'last_updated': attributes.get('last_updated', None),
                        'network_info': {
                            'country': country,
                            'as_owner': as_owner,
                            'asn': asn,
                            'continent': attributes.get('continent', 'Unknown')
                        }
                    }
                else:
                    raise VirusTotalError(f"VirusTotal API error: {response.status}", vt_operation="ip_reputation")
                    
        except Exception as e:
            logger.error(f"Service error in check_ip_reputation: {type(e).__name__}")
            raise handle_service_error(e, "check_ip_reputation", {"ip_address": ip_address})
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash on VirusTotal"""
        if not self.api_key:
            raise VirusTotalError("VirusTotal API key not configured", vt_operation="file_hash")
        
        try:
            session = await self._get_session()
            url = f"{self.base_url}/files/{file_hash}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    # Extract reputation data
                    last_analysis_stats = attributes.get('last_analysis_stats', {})
                    malicious_count = last_analysis_stats.get('malicious', 0)
                    suspicious_count = last_analysis_stats.get('suspicious', 0)
                    total_count = sum(last_analysis_stats.values())
                    
                    # Calculate score (0-100, higher = more malicious)
                    if total_count > 0:
                        score = int((malicious_count + suspicious_count) / total_count * 100)
                    else:
                        score = 0
                    
                    # Determine verdict
                    if malicious_count > 0:
                        verdict = 'malicious'
                    elif suspicious_count > 0:
                        verdict = 'suspicious'
                    elif total_count > 0:
                        verdict = 'clean'
                    else:
                        verdict = 'unknown'
                    
                    return {
                        'available': True,
                        'verdict': verdict,
                        'score': score,
                        'link': f"https://www.virustotal.com/gui/file/{file_hash}/detection",
                        'malicious_count': malicious_count,
                        'suspicious_count': suspicious_count,
                        'total_count': total_count,
                        'file_type': attributes.get('type_description', 'Unknown'),
                        'file_size': attributes.get('size', 0)
                    }
                elif response.status == 404:
                    # File hash not found in VirusTotal database
                    logger.info(f"File hash not found in VirusTotal database: {file_hash[:16]}...")
                    return {
                        'available': False,
                        'verdict': 'unknown',
                        'score': 0,
                        'link': f"https://www.virustotal.com/gui/file/{file_hash}/detection",
                        'malicious_count': 0,
                        'suspicious_count': 0,
                        'total_count': 0,
                        'file_type': 'Unknown',
                        'file_size': 0,
                        'error': 'File hash not found in VirusTotal database'
                    }
                else:
                    raise VirusTotalError(f"VirusTotal API error: {response.status}", vt_operation="file_hash")
                    
        except Exception as e:
            logger.error(f"Service error in check_file_hash: {type(e).__name__}")
            raise handle_service_error(e, "check_file_hash", {"file_hash": file_hash})
    
    async def analyze_attachments(self, attachment_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze multiple attachments with VirusTotal"""
        if not self.api_key:
            raise VirusTotalError("VirusTotal API key not configured", vt_operation="attachment_analysis")
        
        if not attachment_details:
            logger.info("No attachment details provided for VirusTotal analysis")
            return []
        
        logger.info(f"Starting VirusTotal analysis for {len(attachment_details)} attachments")
        results = []
        
        for i, attachment in enumerate(attachment_details, 1):
            try:
                filename = attachment.get('filename', 'unknown')
                logger.info(f"Processing attachment {i}/{len(attachment_details)}: {filename}")
                
                # Validate attachment data
                if not isinstance(attachment, dict):
                    logger.warning(f"Invalid attachment data format for attachment {i}: {type(attachment)}")
                    results.append({
                        'filename': filename,
                        'content_type': attachment.get('content_type', 'unknown'),
                        'size': attachment.get('size', 0),
                        'virustotal': {
                            'available': False,
                            'error': 'Invalid attachment data format',
                            'verdict': 'unknown',
                            'score': 0
                        }
                    })
                    continue
                
                # Get SHA256 hash
                sha256_hash = attachment.get('hash_sha256')
                if not sha256_hash:
                    logger.warning(f"No SHA256 hash available for attachment {filename}")
                    results.append({
                        **attachment,
                        'virustotal': {
                            'available': False,
                            'error': 'No SHA256 hash available',
                            'verdict': 'unknown',
                            'score': 0
                        }
                    })
                    continue
                
                # Validate hash format
                if not isinstance(sha256_hash, str) or len(sha256_hash) != 64:
                    logger.warning(f"Invalid SHA256 hash format for attachment {filename}: {sha256_hash}")
                    results.append({
                        **attachment,
                        'virustotal': {
                            'available': False,
                            'error': 'Invalid SHA256 hash format',
                            'verdict': 'unknown',
                            'score': 0
                        }
                    })
                    continue
                
                # Check with VirusTotal
                logger.debug(f"Checking VirusTotal for attachment {filename} with hash: {sha256_hash[:16]}...")
                vt_result = await self.check_file_hash(sha256_hash)
                
                results.append({
                    **attachment,
                    'virustotal': vt_result
                })
                
                logger.info(f"VirusTotal analysis completed for {filename}: {vt_result.get('verdict', 'unknown')}")
                
                # Rate limiting - be respectful to VirusTotal API
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error analyzing attachment {i} ({attachment.get('filename', 'unknown')}): {type(e).__name__}: {str(e)}")
                results.append({
                    **attachment,
                    'virustotal': {
                        'available': False,
                        'error': f'Analysis failed: {type(e).__name__}',
                        'verdict': 'unknown',
                        'score': 0
                    }
                })
        
        # Log summary
        successful_analyses = len([r for r in results if r.get('virustotal', {}).get('available', False)])
        malicious_count = len([r for r in results if r.get('virustotal', {}).get('verdict') == 'malicious'])
        suspicious_count = len([r for r in results if r.get('virustotal', {}).get('verdict') == 'suspicious'])
        
        logger.info(f"VirusTotal attachment analysis summary: {successful_analyses}/{len(attachment_details)} successful, {malicious_count} malicious, {suspicious_count} suspicious")
        
        return results

# Global instance
virustotal_service = VirusTotalService() 