from pydantic import BaseModel, EmailStr

class AuthenticationRequest(BaseModel):
  email: EmailStr
  password: str