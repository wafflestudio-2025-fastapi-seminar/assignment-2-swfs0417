from fastapi import APIRouter
from fastapi import Depends, Cookie, Header
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import Response

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import AuthenticationRequest, Token
from src.common.custom_exception import CustomException


from argon2 import PasswordHasher, exceptions
from authlib.jose import jwt
import authlib.jose.errors as JWTerror
from datetime import datetime, timedelta

ph = PasswordHasher()

auth_router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='access_token')

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60
SECRET_KEY = "3a8b9b1b11f11eabb7bd5d9c10d9ae8fc7ec47a6403fde2436c4168ba384157e"
JWT_HEADER = {"alg": "HS256", "typ": "JWT"}


def new_token(user_email: str) -> Token:
  payload_acc = {"sub": user_email, "exp": (datetime.now() + timedelta(minutes=SHORT_SESSION_LIFESPAN)).timestamp()}
  payload_ref = {"sub": user_email, "exp": (datetime.now() + timedelta(minutes=LONG_SESSION_LIFESPAN)).timestamp()}

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

      return new_token(user["email"])
  else:
    raise exceptions.VerifyMismatchError


@auth_router.post("/token/refresh")
def refresh_token(access_token: str | None = Header(default=None)) -> Token:
  if not access_token:
    raise CustomException(401, "ERR_009", "UNAUTHENTICATED")
  token = access_token.split(" ")[1]
  if (token in blocked_token_db):
    raise CustomException(401, "ERR_008", "INVALID TOKEN")
  try:
    if access_token.split(" ")[0] != "Bearer":
      raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
    # print(token)
    payload = jwt.decode(token, SECRET_KEY)
    # print(payload.get('exp'), datetime.now().timestamp())
    if payload.get('exp') < datetime.now().timestamp():
      raise CustomException(401, "ERR_008", "INVALID TOKEN")
  except JWTerror.DecodeError:
    raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
  user_email = payload.get('sub')
  for user in user_db:
    if user['email'] == user_email:
      blocked_token_db[token] = payload.get('exp')
      return new_token(user_email)
  else:
    raise CustomException(401, "ERR_008", "INVALID TOKEN")

@auth_router.delete("/token")
def delete_token(access_token: str | None = Header(default=None)):
  if not access_token:
    raise CustomException(401, "ERR_009", "UNAUTHENTICATED")
  token = access_token.split(" ")[1]
  if (token in blocked_token_db):
    raise CustomException(401, "ERR_008", "INVALID TOKEN")
  try:
    if access_token.split(" ")[0] != "Bearer":
      raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
    # print(token)
    payload = jwt.decode(token, SECRET_KEY)
    # print(payload.get('exp'), datetime.now().timestamp())
    if payload.get('exp') < datetime.now().timestamp():
      raise CustomException(401, "ERR_008", "INVALID TOKEN")
  except JWTerror.DecodeError:
    raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
  user_email = payload.get('sub')
  for user in user_db:
    if user['email'] == user_email:
      blocked_token_db[token] = payload.get('exp')
      return Response(status_code=204)
  else:
    raise CustomException(401, "ERR_008", "INVALID TOKEN")


# @auth_router.post("/session")


# @auth_router.delete("/session")
