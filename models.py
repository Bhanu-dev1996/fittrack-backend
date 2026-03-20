from sqlalchemy import Column, Integer, String, Float, DateTime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    age = Column(Integer)
    height = Column(Float)
    weight = Column(Float)
    goal = Column(String)
    profile_image_path = Column(String, nullable=True)

    reset_token_hash = Column(String, nullable=True, index=True)
    reset_token_expires_at = Column(DateTime, nullable=True)