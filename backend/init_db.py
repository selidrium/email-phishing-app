import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.utils.database import engine
from backend.models.sqlalchemy_models import Base

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("✅ Database initialized.")
