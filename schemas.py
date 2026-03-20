from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    age: int
    height: float
    weight: float
    goal: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8)
    confirm_password: str = Field(min_length=8)

class ProfileUpdate(BaseModel):
    name: str
    email: EmailStr
    age: int
    height: float
    weight: float
    goal: str    