from fastapi import APIRouter
from fastapi import Depends, Cookie

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import AuthenticationRequest, Token

from argon2 import PasswordHasher, exceptions
from authlib.jose import jwt
import time

ph = PasswordHasher()

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60
SECRET_KEY = "3a8b9b1b11f11eabb7bd5d9c10d9ae8fc7ec47a6403fde2436c4168ba384157e"
JWT_HEADER = {"alg": "HS256", "typ": "JWT"}


def new_token(user_id: int) -> Token:
  payload_acc = {"sub": user_id, "exp": time.time() + SHORT_SESSION_LIFESPAN}
  payload_ref = {"sub": user_id, "exp": time.time() + LONG_SESSION_LIFESPAN}

  token = {
    "access_token": jwt.encode(JWT_HEADER, payload_acc, SECRET_KEY),
    "refresh_token": jwt.encode(JWT_HEADER, payload_ref, SECRET_KEY),
  }
  return Token(**token)

# def verify_token(token: )


@auth_router.post("/token")
def token_login(request: AuthenticationRequest) -> Token:
  for user in user_db:
    if user["email"] == request.email:
      ph.verify(user["hashed_password"], request.password)

      return new_token(user["user_id"])
  else:
    raise exceptions.VerifyMismatchError


@auth_router.post("/token/refresh")
def refresh_token() -> Token:
  pass


# @auth_router.delete("/token")


# @auth_router.post("/session")


# @auth_router.delete("/session")
