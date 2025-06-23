import logging
import sys
from pythonjsonlogger import jsonlogger
from typing import Optional
import uuid
from contextvars import ContextVar

# Context variable to store correlation ID for the current request
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)

class CorrelationIdFilter(logging.Filter):
    """Filter to add correlation ID to log records"""
    
    def filter(self, record):
        record.correlation_id = correlation_id_var.get() or 'no-correlation-id'
        return True

class StructuredLogger:
    """Structured logger with correlation ID support"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.addFilter(CorrelationIdFilter())
    
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for current context"""
        correlation_id_var.set(correlation_id)
    
    def clear_correlation_id(self):
        """Clear correlation ID from current context"""
        correlation_id_var.set(None)
    
    def info(self, message: str, **kwargs):
        """Log info message with structured data"""
        extra = {'correlation_id': correlation_id_var.get() or 'no-correlation-id'}
        extra.update(kwargs)
        self.logger.info(message, extra=extra)
    
    def error(self, message: str, **kwargs):
        """Log error message with structured data"""
        extra = {'correlation_id': correlation_id_var.get() or 'no-correlation-id'}
        # Handle exc_info separately to avoid conflicts
        exc_info = kwargs.pop('exc_info', None)
        extra.update(kwargs)
        self.logger.error(message, extra=extra, exc_info=exc_info)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with structured data"""
        extra = {'correlation_id': correlation_id_var.get() or 'no-correlation-id'}
        extra.update(kwargs)
        self.logger.warning(message, extra=extra)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with structured data"""
        extra = {'correlation_id': correlation_id_var.get() or 'no-correlation-id'}
        extra.update(kwargs)
        self.logger.debug(message, extra=extra)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with structured data"""
        extra = {'correlation_id': correlation_id_var.get() or 'no-correlation-id'}
        extra.update(kwargs)
        self.logger.critical(message, extra=extra)

def setup_structured_logging():
    """Setup structured logging with JSON formatter"""
    
    # Create JSON formatter with correlation ID
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(levelname)s %(name)s %(message)s %(correlation_id)s %(user_id)s %(endpoint)s %(method)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Setup file handler for production
    try:
        file_handler = logging.FileHandler('logs/app.log')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
    except FileNotFoundError:
        # Create logs directory if it doesn't exist
        import os
        os.makedirs('logs', exist_ok=True)
        file_handler = logging.FileHandler('logs/app.log')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add our handlers
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # Suppress noisy loggers
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
    logging.getLogger('uvicorn.error').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance"""
    return StructuredLogger(name)

def generate_correlation_id() -> str:
    """Generate a unique correlation ID"""
    return str(uuid.uuid4())

def get_correlation_id() -> Optional[str]:
    """Get current correlation ID"""
    return correlation_id_var.get()

def set_correlation_id(correlation_id: str):
    """Set correlation ID for current context"""
    correlation_id_var.set(correlation_id) 