# 🎯 Analysis Scoring Logic - Complete Breakdown

This document provides a comprehensive breakdown of how the phishing detection system calculates risk scores and determines threat levels.

## 📊 Overview

The phishing detection system uses a **multi-layered scoring approach** that combines:
- **Static analysis** of email components
- **External threat intelligence** (VirusTotal)
- **Forensic indicators** and authentication checks
- **Weighted scoring** with different priorities for different threat types

## 🏗️ Architecture

The scoring system is implemented across **three main services**:

1. **`PhishingDetector`** - Core scoring engine for individual components
2. **`UploadService`** - Overall risk calculation and threat weighting
3. **`EmailForensics`** - Additional forensic indicators and authentication analysis

---

## 🧠 Core Scoring Engine: PhishingDetector

**Location**: `backend/services/phishing_detector.py`

### Component Scoring Weights

```python
def _calculate_score(self, analysis: Dict) -> int:
    total_score = 0
    
    # IP Analysis gets highest weight (40%) - CRITICAL FACTOR
    total_score += analysis['ip_analysis']['score'] * 0.40
    
    # Attachments get high weight (25%) - HIGH RISK
    total_score += analysis['attachment_analysis']['score'] * 0.25
    
    # Headers get medium weight (15%) - Authentication importance
    total_score += analysis['header_analysis']['score'] * 0.15
    
    # URLs get medium weight (10%)
    total_score += analysis['url_analysis']['score'] * 0.10
    
    # Content gets lower weight (7%)
    total_score += analysis['content_analysis']['score'] * 0.07
    
    # Sender gets lowest weight (3%)
    total_score += analysis['sender_analysis']['score'] * 0.03
    
    return min(100, int(total_score))
```

### Individual Component Scoring

#### 🔍 Sender Analysis (0-50 points)

| Indicator | Points | Description |
|-----------|--------|-------------|
| Suspicious sender format | +10 | Numeric patterns, unusual formats |
| Suspicious domain keywords | +15 | Domains with 'badactor', 'malicious', 'phish', etc. |
| Mismatched Reply-To | +15 | Reply-To differs from From header |
| Generic sender names | +5 | 'support', 'admin', 'noreply', 'info', 'service' |

**Suspicious Domain Keywords**:
```python
self.suspicious_keywords_in_domains = [
    'badactor', 'malicious', 'phish', 'fake', 'scam', 'hack',
    'steal', 'virus', 'malware', 'trojan', 'spam', 'evil',
    'suspicious', 'dangerous', 'fraud', 'cheat', 'stealer'
]
```

#### 📝 Content Analysis (0-100+ points)

| Indicator | Points | Description |
|-----------|--------|-------------|
| Urgency indicators | +8 per keyword | Each urgency word found |
| Suspicious keywords | +10 per keyword | Each suspicious phrase found |
| Poor grammar/spelling | +10 | Excessive long words, poor formatting |
| Excessive exclamation marks | +5 | More than 3 exclamation marks |

**Urgency Keywords**:
```python
self.urgency_keywords = [
    'urgent', 'immediate', 'action required', 'account suspended',
    'verify now', 'confirm immediately', 'security alert',
    'unauthorized access', 'account locked', 'payment overdue',
    'suspended', 'blocked', 'restricted', 'expired', 'critical'
]
```

**Suspicious Keywords**:
```python
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
```

#### 🔗 URL Analysis (0-100+ points)

| Indicator | Points | Description |
|-----------|--------|-------------|
| URL shorteners | +15 | bit.ly, tinyurl.com, goo.gl, etc. |
| Suspicious domain names | +20 | Domains with malicious keywords |
| IP addresses in URLs | +20 | Direct IP addresses instead of domains |
| Suspicious TLDs | +10 | .tk, .ml, .ga, .cf, .gq |
| Excessive subdomains | +8 | More than 2 subdomain levels |

**Suspicious Domains (URL Shorteners)**:
```python
self.suspicious_domains = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'v.gd',
    'ow.ly', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to'
]
```

#### 🛡️ Header Analysis (0-100+ points)

| Indicator | Points | Description |
|-----------|--------|-------------|
| SPF check failed | +30 | Sender Policy Framework failure |
| DKIM verification failed | +20 | Digital signature verification failure |
| DMARC check failed | +25 | Domain-based Message Authentication failure |
| No authentication headers | +15 | Missing SPF, DKIM, and DMARC |
| Insufficient routing hops | +10 | Less than 2 Received headers |
| Suspicious routing | +15 | localhost, 127.0.0.1 in routing |

#### 📎 Attachment Analysis (0-100+ points)

| Indicator | Points | Description |
|-----------|--------|-------------|
| Executable files | +40 | .exe, .bat, .cmd, .com, .pif, .scr, .vbs, .js, .jar, .msi |
| Dangerous double extensions | +35 | .pdf.exe, .doc.exe, .xls.exe, etc. |
| Regular double extensions | +25 | Any double extension pattern |
| Archive files | +15 | .zip, .rar, .7z, .tar, .gz, .arj, .ace |
| Suspicious filenames | +8 | 'invoice', 'document', 'scan', 'receipt', etc. |

**Suspicious Filenames**:
```python
suspicious_names = [
    'invoice', 'document', 'scan', 'receipt', 'statement', 
    'order', 'nueva orden'
]
```

#### 🌐 IP Reputation Analysis (0-100+ points)

| Indicator | Points | Description |
|-----------|--------|-------------|
| Malicious IP (VirusTotal) | +50 | IP flagged as malicious |
| Suspicious IP (VirusTotal) | +30 | IP flagged as suspicious |
| Poor reputation score | +25 | Reputation score < -50 |
| Negative reputation score | +15 | Reputation score < 0 |
| Threat categories | +10 per category | Each threat category identified |
| VPN/Proxy provider | +20 | IP from VPN or proxy service |
| High-risk country | +10 | IP from designated high-risk countries |

---

## 🔬 Overall Risk Calculation: UploadService

**Location**: `backend/services/upload.py`

This service combines all analysis results with enhanced threat weighting:

```python
def _calculate_overall_risk(self, phishing_analysis, forensics_analysis, vt_results):
    overall_score = 0
    
    # Phishing score (25% weight)
    overall_score += phishing_analysis.get('score', 0) * 0.25
    
    # Forensic indicators (5% weight)
    forensic_score = sum(indicator.get('risk_score', 0) for indicator in forensic_indicators)
    overall_score += forensic_score * 0.05
    
    # Authentication failures (5% weight)
    overall_score += auth_analysis.get('overall_score', 0) * 0.05
    
    # VirusTotal IP reputation (25% weight) - CRITICAL FACTOR
    if ip_reputation.get('verdict') == 'malicious':
        overall_score += 80 * 0.25  # Malicious IP is critical
    elif ip_reputation.get('verdict') == 'suspicious':
        overall_score += 50 * 0.25
    
    # VirusTotal file hash (20% weight)
    if file_hash.get('verdict') == 'malicious':
        overall_score += 70 * 0.2
    
    # Attachment analysis (20% weight) - CRITICAL FACTOR
    # High-risk patterns get 60+ points, archives 40+, others 25+
    
    return min(int(overall_score), 100)
```

### Weight Distribution

| Component | Weight | Reason |
|-----------|--------|---------|
| **IP Reputation** | 25% | **CRITICAL** - External threat intelligence |
| **Attachments** | 20% | **CRITICAL** - High malware risk |
| **File Hash** | 20% | **HIGH** - VirusTotal file analysis |
| **Phishing Score** | 25% | **MEDIUM** - Static analysis results |
| **Forensic Indicators** | 5% | **LOW** - Additional context |
| **Authentication** | 5% | **LOW** - Header validation |

---

## 🔍 Forensic Analysis: EmailForensics

**Location**: `backend/services/email_forensics.py`

Provides additional forensic indicators with risk scores:

```python
def _identify_forensic_indicators(self, msg):
    forensic_checks = [
        ('Message-ID missing', lambda: not msg.get('Message-ID'), 15),
        ('No Received headers', lambda: not msg.get_all('Received'), 20),
        ('Suspicious routing', lambda: self._check_suspicious_routing(msg), 25),
        ('Authentication failure', lambda: self._check_auth_failures(msg), 30),
        ('Header manipulation', lambda: self._check_header_manipulation(msg), 20)
    ]
```

### Forensic Indicator Scoring

| Indicator | Risk Score | Severity |
|-----------|------------|----------|
| Authentication failure | 30 | High |
| Suspicious routing | 25 | High |
| Header manipulation | 20 | Medium |
| No Received headers | 20 | Medium |
| Message-ID missing | 15 | Low |
| Insufficient routing hops | 10 | Low |

---

## 📊 Risk Level Thresholds

```python
def _get_risk_level(self, score: int) -> str:
    if score >= 60:      # HIGH RISK
        return 'high'
    elif score >= 40:    # MEDIUM RISK
        return 'medium'
    elif score >= 20:    # LOW RISK
        return 'low'
    else:                # VERY LOW RISK
        return 'very_low'
```

### Risk Level Breakdown

| Score Range | Risk Level | Description | Action |
|-------------|------------|-------------|---------|
| 0-19 | **Very Low** | Likely legitimate | Allow |
| 20-39 | **Low** | Some concerns | Review |
| 40-59 | **Medium** | Suspicious | Block/Review |
| 60+ | **High** | Highly suspicious | Block |

---

## 🎯 Key Scoring Features

### 1. **IP Reputation Dominance**
- IP analysis gets **40% weight** - highest priority
- External threat intelligence heavily weighted
- Malicious IPs can single-handedly trigger high-risk classification

### 2. **Attachment Risk Priority**
- Dangerous files get maximum points (40+)
- Double extensions heavily penalized (35+ points)
- Executables immediately flagged (40 points)

### 3. **Authentication Failures**
- SPF/DKIM/DMARC failures heavily penalized
- SPF failure: +30 points
- DKIM failure: +20 points
- DMARC failure: +25 points

### 4. **VirusTotal Integration**
- External threat intelligence heavily weighted
- File hash analysis: 20% weight
- IP reputation: 25% weight
- Attachment analysis: 20% weight

### 5. **Multi-Layer Analysis**
- Combines static analysis + external intelligence + forensic indicators
- Weighted scoring prevents single factor domination
- Comprehensive threat assessment

---

## 🔧 Customization Points

### Adding New Keywords

**Urgency Keywords**:
```python
# In PhishingDetector.__init__()
self.urgency_keywords.append('new_urgency_word')
```

**Suspicious Keywords**:
```python
# In PhishingDetector.__init__()
self.suspicious_keywords.append('new_suspicious_phrase')
```

**Suspicious Domains**:
```python
# In PhishingDetector.__init__()
self.suspicious_domains.append('new_suspicious_domain.com')
```

### Adjusting Scoring Weights

**Component Weights**:
```python
# In _calculate_score() method
total_score += analysis['ip_analysis']['score'] * 0.40      # 40% weight
total_score += analysis['attachment_analysis']['score'] * 0.25  # 25% weight
# Adjust these multipliers to change component importance
```

**Risk Thresholds**:
```python
# In _get_risk_level() method
if score >= 60:      # Change 60 to adjust high-risk threshold
    return 'high'
elif score >= 40:    # Change 40 to adjust medium-risk threshold
    return 'medium'
```

---

## 📁 File Locations

| Component | File Path | Lines |
|-----------|-----------|-------|
| **Main scoring algorithm** | `backend/services/phishing_detector.py` | 400-465 |
| **Overall risk calculation** | `backend/services/upload.py` | 365-430 |
| **Forensic indicators** | `backend/services/email_forensics.py` | 580-620 |
| **Risk level thresholds** | `backend/services/phishing_detector.py` | 457-465 |
| **Keyword definitions** | `backend/services/phishing_detector.py` | 20-40 |

---

## 🚀 Performance Considerations

### Scoring Efficiency
- **Linear time complexity** O(n) for most analysis
- **Regex patterns** optimized for common threats
- **Caching** of analysis results where possible

### Memory Usage
- **Streaming analysis** for large emails
- **Efficient data structures** for keyword matching
- **Minimal object creation** during analysis

---

## 🔍 Debugging and Monitoring

### Logging
- **Detailed scoring breakdown** in logs
- **Individual component scores** logged
- **Indicator aggregation** tracked

### Metrics
- **Score distribution** across analyzed emails
- **Component contribution** to final scores
- **False positive/negative** tracking

---

## 📚 References

- **VirusTotal API**: External threat intelligence
- **RFC 5321**: Email message format standards
- **SPF/DKIM/DMARC**: Email authentication protocols
- **Common phishing patterns**: Industry threat intelligence

---

*This document is automatically generated and should be updated when scoring logic changes.*
