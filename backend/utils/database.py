from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.models.sqlalchemy_models import Base
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def init_db():
    """Initialize database tables"""
    # Create all tables
    Base.metadata.create_all(bind=engine) 