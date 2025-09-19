from argon2 import exceptions
from src.users.errors import InvalidAccountException

from pydantic import BaseModel

class User(BaseModel):
  user_id: int
  email: str
  hashed_password: str
  name: str
  phone_number: str
  height: float
  bio: str | None = None

blocked_token_db = {}
user_db: list[User] = []
session_db = {}

def find_user_index_by_email(email: str):
  for i in range(len(user_db)):
    if user_db[i].email == email:
      return i
  raise InvalidAccountException