import os
import sqlite3
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from backend.models.sqlalchemy_models import Base, User
from backend.utils.logging_config import get_logger

logger = get_logger(__name__)

def init_db():
    """Initialize database with proper schema and migrations"""
    database_url = os.getenv("DATABASE_URL", "sqlite:///./database/phishing_detection.db")
    
    # Create database directory if it doesn't exist
    if database_url.startswith("sqlite:///"):
        db_path = database_url.replace("sqlite:///", "")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    engine = create_engine(database_url)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Check if we need to migrate existing data
    migrate_existing_data(engine)
    
    logger.info("Database initialized successfully")

def migrate_existing_data(engine):
    """Migrate existing data to new schema"""
    try:
        # Check if is_admin column exists
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'is_admin' not in columns:
                logger.info("Adding is_admin column to users table")
                conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE"))
                
                # Set first user as admin
                conn.execute(text("UPDATE users SET is_admin = TRUE WHERE id = (SELECT MIN(id) FROM users)"))
                
            if 'created_at' not in columns:
                logger.info("Adding created_at column to users table")
                conn.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME"))
                
                # Set default creation time for existing users
                conn.execute(text("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
                
            conn.commit()
            logger.info("Database migration completed successfully")
            
    except Exception as e:
        logger.error(f"Migration error: {e}")
        # If migration fails, recreate the database
        logger.info("Recreating database with new schema")
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
