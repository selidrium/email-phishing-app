from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(self, id, email, password_hash, created_at=None):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.created_at = created_at or datetime.utcnow()

    @staticmethod
    def create(email, password):
        """Create a new user with hashed password"""
        password_hash = generate_password_hash(password)
        # In a real application, you would save this to a database
        # For now, we'll just return a new User instance
        return User(id=1, email=email, password_hash=password_hash)

    def check_password(self, password):
        """Check if the provided password matches the hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        } 