from pydantic import BaseModel, EmailStr

class AuthenticationRequest(BaseModel):
  email: EmailStr
  password: str

class Token(BaseModel):
  access_token: str
  refresh_token: str