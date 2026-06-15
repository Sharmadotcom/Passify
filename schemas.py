import re
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field, field_validator

class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        # Alphanumeric characters, underscores, and dashes only
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain alphanumeric characters, underscores, and dashes')
        return v

class UserLoginSchema(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)

class VaultItemSchema(BaseModel):
    website: str = Field(..., min_length=1, max_length=255)
    site_username: str = Field(..., min_length=1, max_length=255)
    site_password: str = Field(..., min_length=1, max_length=255)

class EmailUpdateSchema(BaseModel):
    # Allow empty email string to clear/reset email, or must be valid
    email: str = Field("", max_length=254)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        v_stripped = v.strip()
        if not v_stripped:
            return ""
        # Basic validation for email format
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', v_stripped):
            raise ValueError('Invalid email address format')
        return v_stripped

class MasterPasswordSchema(BaseModel):
    master_password: str = Field(..., min_length=1, max_length=128)
