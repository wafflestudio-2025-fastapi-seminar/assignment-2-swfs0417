from fastapi import APIRouter
from fastapi import Depends, Cookie

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import AuthenticationRequest

from argon2 import PasswordHasher, exceptions

ph = PasswordHasher()

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

@auth_router.post("/token")
def token_login(request: AuthenticationRequest):
  for user in user_db:
    if user['email'] == request.email:
      print(ph.hash(request.password))
      ph.verify(user['hashed_password'], request.password)
      
      return #token
  else:
    raise exceptions.VerifyMismatchError


# @auth_router.post("/token/refresh")


# @auth_router.delete("/token")


# @auth_router.post("/session")


# @auth_router.delete("/session")
