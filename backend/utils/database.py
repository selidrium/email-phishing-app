import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.sqlalchemy_models import Base
from backend.init_db import init_db

# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/phishing_detection.db")

# Create engine
engine = create_engine(DATABASE_URL)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def initialize_database():
    """Initialize database with proper schema"""
    init_db() 