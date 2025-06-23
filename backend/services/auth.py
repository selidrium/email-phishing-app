from passlib.context import CryptContext
from fastapi_jwt_auth import AuthJWT
from fastapi import Depends, HTTPException, status
from backend.models.sqlalchemy_models import User
from sqlalchemy.orm import Session

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(identity: str, Authorize: AuthJWT = Depends()):
    return Authorize.create_access_token(subject=identity) 