"""
Centralized error handling for the phishing detection application.
Provides consistent error response formats across all services.
"""

from fastapi import HTTPException, status
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class PhishingAppException(HTTPException):
    """Base exception class for the phishing detection application."""
    
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code
        self.context = context or {}
        
        # Log the error with context
        logger.error(f"PhishingAppException: {detail} (Code: {error_code}, Status: {status_code})", 
                    extra={"context": self.context})
    
    @property
    def message(self) -> str:
        """Return the error message (alias for detail)."""
        return self.detail

class ValidationError(PhishingAppException):
    """Raised when input validation fails."""
    
    def __init__(self, detail: str, field: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            error_code="VALIDATION_ERROR",
            context={"field": field} if field else {}
        )

class AuthenticationError(PhishingAppException):
    """Raised when authentication fails."""
    
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="AUTHENTICATION_ERROR"
        )

class AuthorizationError(PhishingAppException):
    """Raised when authorization fails."""
    
    def __init__(self, detail: str = "Access denied"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            error_code="AUTHORIZATION_ERROR"
        )

class NotFoundError(PhishingAppException):
    """Raised when a resource is not found."""
    
    def __init__(self, resource: str, resource_id: Optional[str] = None):
        detail = f"{resource} not found"
        if resource_id:
            detail += f" with id: {resource_id}"
        
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
            error_code="NOT_FOUND",
            context={"resource": resource, "resource_id": resource_id}
        )

class FileProcessingError(PhishingAppException):
    """Raised when file processing fails."""
    
    def __init__(self, detail: str, file_info: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            error_code="FILE_PROCESSING_ERROR",
            context={"file_info": file_info} if file_info else {}
        )

class AnalysisError(PhishingAppException):
    """Raised when email analysis fails."""
    
    def __init__(self, detail: str, analysis_step: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="ANALYSIS_ERROR",
            context={"analysis_step": analysis_step} if analysis_step else {}
        )

class VirusTotalError(PhishingAppException):
    """Raised when VirusTotal API operations fail."""
    
    def __init__(self, detail: str, vt_operation: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
            error_code="VIRUSTOTAL_ERROR",
            context={"vt_operation": vt_operation} if vt_operation else {}
        )

class DatabaseError(PhishingAppException):
    """Raised when database operations fail."""
    
    def __init__(self, detail: str, operation: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="DATABASE_ERROR",
            context={"operation": operation} if operation else {}
        )

class ReportGenerationError(PhishingAppException):
    """Raised when report generation fails."""
    
    def __init__(self, detail: str, report_type: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="REPORT_GENERATION_ERROR",
            context={"report_type": report_type} if report_type else {}
        )

# Utility functions for consistent error handling
def handle_service_error(error: Exception, operation: str, context: Optional[Dict[str, Any]] = None) -> PhishingAppException:
    """Convert service-level exceptions to standardized PhishingAppException."""
    
    if isinstance(error, PhishingAppException):
        return error
    
    # Log the error type and operation, but NOT the full error message
    error_type = type(error).__name__
    logger.error(f"Service error in {operation}: {error_type}", 
                extra={"context": context, "error_type": error_type, "operation": operation})
    
    # Convert to appropriate exception type with safe messages
    error_str = str(error).lower()
    
    if "validation" in error_str or "invalid" in error_str:
        return ValidationError("Input validation failed")
    elif "not found" in error_str or "missing" in error_str:
        return NotFoundError("Resource", context.get("resource_id") if context else None)
    elif "authentication" in error_str or "unauthorized" in error_str:
        return AuthenticationError("Authentication failed")
    elif "virustotal" in error_str:
        return VirusTotalError("External security service unavailable", context.get("vt_operation") if context else None)
    elif "database" in error_str or "sql" in error_str:
        return DatabaseError("Database operation failed", context.get("operation") if context else None)
    elif "file" in error_str or "upload" in error_str:
        return FileProcessingError("File processing failed", context.get("file_info") if context else None)
    elif "report" in error_str or "pdf" in error_str or "csv" in error_str:
        return ReportGenerationError("Report generation failed", context.get("report_type") if context else None)
    else:
        return AnalysisError("Analysis operation failed", context.get("analysis_step") if context else None)

def log_error_safely(error: Exception, operation: str, context: Optional[Dict[str, Any]] = None):
    """Log error information safely without exposing sensitive data."""
    error_type = type(error).__name__
    logger.error(f"Error in {operation}: {error_type}", 
                extra={
                    "context": context, 
                    "error_type": error_type, 
                    "operation": operation,
                    "has_error_message": bool(str(error))
                })

def create_error_response(error: PhishingAppException) -> Dict[str, Any]:
    """Create a standardized error response format."""
    return {
        "error": {
            "code": error.error_code,
            "message": error.detail,
            "status_code": error.status_code,
            "context": error.context
        }
    } 