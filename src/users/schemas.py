import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.common.database import user_db

import src.users.errors as errors

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    @field_validator('password', mode='after')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise errors.InvalidPasswordException()
        return v
      
    @field_validator('email', mode='after')
    @classmethod
    def validate_email(cls, v):
        global user_db
        emails = [x['email'] for x in user_db]
        if v in emails:
          raise errors.ExistingEmailException()
        return v
    
    @field_validator('phone_number', mode='after')
    @classmethod
    def validate_phone_number(cls, v):
        if not re.match(r"010-[0-9]{4}-[0-9]{4}", v):
            raise errors.InvalidPhoneNumberException()
        return v

    @field_validator('bio', mode='after')
    @classmethod
    def validate_bio(cls, v):
        if len(v) > 500:
            raise errors.TooLongBioException()
        return v

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float