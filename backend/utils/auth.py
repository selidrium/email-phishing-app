from fastapi import Depends, status
from fastapi_jwt_auth import AuthJWT
from sqlalchemy.orm import Session
from backend.models.sqlalchemy_models import User
from backend.utils.database import get_db
from backend.utils.exceptions import AuthenticationError, NotFoundError

async def get_current_user(Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)) -> dict:
    """Get current authenticated user"""
    try:
        Authorize.jwt_required()
        username = Authorize.get_jwt_subject()
        
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise NotFoundError("User", username)
        
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    except Exception as e:
        if isinstance(e, (NotFoundError, AuthenticationError)):
            raise
        raise AuthenticationError("Invalid token") 