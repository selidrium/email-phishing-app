from sqlalchemy import text
from sqlalchemy.orm import Session
from backend.utils.database import SessionLocal
import logging
import time
from typing import Dict, Any

logger = logging.getLogger(__name__)

class MonitoringService:
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        
    def check_database_health(self) -> Dict[str, Any]:
        """Check database connection and health"""
        try:
            db = SessionLocal()
            # Test database connection
            result = db.execute(text("SELECT 1"))
            result.fetchone()
            db.close()
            
            return {
                "status": "healthy",
                "connection": "ok",
                "response_time": "fast"
            }
        except Exception as e:
            logger.error(f"Service error in database_health_check: {type(e).__name__}")
            return {
                "status": "unhealthy",
                "connection": "failed",
                "error": str(e)
            }
    
    def get_uptime(self) -> float:
        """Get application uptime in seconds"""
        return time.time() - self.start_time
    
    def increment_request_count(self):
        """Increment request counter"""
        self.request_count += 1
    
    def increment_error_count(self):
        """Increment error counter"""
        self.error_count += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get application statistics"""
        uptime = self.get_uptime()
        error_rate = (self.error_count / self.request_count * 100) if self.request_count > 0 else 0
        
        return {
            "uptime_seconds": uptime,
            "uptime_formatted": self._format_uptime(uptime),
            "total_requests": self.request_count,
            "total_errors": self.error_count,
            "error_rate_percent": round(error_rate, 2),
            "requests_per_minute": round(self.request_count / (uptime / 60), 2) if uptime > 0 else 0
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {secs}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"

# Global monitoring instance
monitoring_service = MonitoringService()

def setup_monitoring():
    """Setup monitoring configuration"""
    logger.info("Monitoring setup completed")
    # This function can be extended with additional monitoring setup
    # For now, it just logs that monitoring is ready 