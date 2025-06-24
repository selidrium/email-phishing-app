import re
import html
from typing import Optional
from backend.utils.exceptions import ValidationError

def sanitize_html(text: str) -> str:
    """Sanitize HTML content to prevent XSS attacks"""
    if not text:
        return text
    
    # HTML escape the content
    sanitized = html.escape(text)
    
    # Remove any remaining script tags and dangerous attributes
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    
    return sanitized

def validate_filename(filename: str) -> str:
    """Validate and sanitize filename"""
    if not filename:
        raise ValidationError("Filename is required")
    
    # Remove path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValidationError("Invalid filename")
    
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        raise ValidationError("Filename too long")
    
    return filename

def validate_email_content(content: str) -> str:
    """Validate and sanitize email content"""
    if not content:
        return content
    
    # Basic content validation
    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        raise ValidationError("Email content too large")
    
    # Sanitize HTML content
    return sanitize_html(content)

def generate_secure_secret_key() -> str:
    """Generate a secure secret key for JWT"""
    import secrets
    return secrets.token_urlsafe(32)

def validate_secret_key(key: str) -> bool:
    """Validate that secret key meets security requirements"""
    if not key or len(key) < 32:
        return False
    
    # Check for common weak keys
    weak_keys = ['secret', 'key', 'password', 'admin', 'test', 'dev', 'development']
    if key.lower() in weak_keys:
        return False
    
    return True 