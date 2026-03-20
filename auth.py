from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from models import User
from passlib.context import CryptContext
import hashlib
import secrets

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
PASSWORD_RESET_EXPIRE_MINUTES = 30

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_user(db, name, email, password, age, height, weight, goal):
    hashed_password = hash_password(password)

    user = User(
        name=name,
        email=email,
        password_hash=hashed_password,
        age=age,
        height=height,
        weight=weight,
        goal=goal,
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def generate_password_reset_token(db: Session, user: User) -> str:
    raw_token = secrets.token_urlsafe(32)
    user.reset_token_hash = hash_reset_token(raw_token)
    user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=PASSWORD_RESET_EXPIRE_MINUTES
    )
    db.commit()
    return raw_token

def get_user_by_reset_token(db: Session, raw_token: str):
    token_hash = hash_reset_token(raw_token)
    user = db.query(User).filter(User.reset_token_hash == token_hash).first()
    if not user:
        return None

    expires_at = user.reset_token_expires_at
    if expires_at is None:
        return None

    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        return None

    return user

def update_password_from_reset(db: Session, user: User, new_password: str):
    user.password_hash = hash_password(new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.commit()


def update_user_profile(db: Session, user: User, name: str, email: str, age: int, height: float, weight: float, goal: str):
    user.name = name
    user.email = email
    user.age = age
    user.height = height
    user.weight = weight
    user.goal = goal
    db.commit()
    db.refresh(user)
    return user    