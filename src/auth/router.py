from fastapi import APIRouter
from fastapi import Depends, Cookie, Header
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import Response

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import AuthenticationRequest, Token
from src.common.custom_exception import CustomException
import uuid

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
  payload_acc = {"sub": user_email, "exp": (datetime.now() + timedelta(minutes=SHORT_SESSION_LIFESPAN))}
  payload_ref = {"sub": user_email, "exp": (datetime.now() + timedelta(minutes=LONG_SESSION_LIFESPAN))}

  token = {
    "access_token": jwt.encode(JWT_HEADER, payload_acc, SECRET_KEY),
    "refresh_token": jwt.encode(JWT_HEADER, payload_ref, SECRET_KEY),
  }
  return Token(**token)

def verify_token(token: str) -> tuple:
  if not token:
    raise CustomException(401, "ERR_009", "UNAUTHENTICATED")
  if token.split(" ")[0] != "Bearer":
    raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
  token = token.split(" ")[1]
  if (token in blocked_token_db):
    raise CustomException(401, "ERR_008", "INVALID TOKEN")
  try:
    # print(token)
    payload = jwt.decode(token, SECRET_KEY)
    # print(payload.get('exp'), datetime.now().timestamp())
    if payload.get('exp') < datetime.now().timestamp():
      raise CustomException(401, "ERR_008", "INVALID TOKEN")
  except JWTerror.DecodeError:
    raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
  user_email = payload.get('sub')
  return user_email, payload, token

def login(idpw: AuthenticationRequest) -> str:
  for user in user_db:
    if user["email"] == idpw.email:
      ph.verify(user["hashed_password"], idpw.password)
      return user["email"]
  raise exceptions.VerifyMismatchError

# def verify_token(token: )


@auth_router.post("/token")
def token_login(request: AuthenticationRequest) -> Token:
  return new_token(login(request))


@auth_router.post("/token/refresh")
def refresh_token(access_token: str | None = Header(default=None)) -> Token:
  user_email, payload, token = verify_token(access_token)
  for user in user_db:
    if user['email'] == user_email:
      blocked_token_db[token] = payload.get('exp')
      return new_token(user_email)
  else:
    raise CustomException(401, "ERR_008", "INVALID TOKEN")

@auth_router.delete("/token")
def delete_token(access_token: str | None = Header(default=None)):
  user_email, payload, token = verify_token(access_token)
  for user in user_db:
    if user['email'] == user_email:
      blocked_token_db[token] = payload.get('exp')
      return Response(status_code=204)
  else:
    raise CustomException(401, "ERR_008", "INVALID TOKEN")


@auth_router.post("/session", status_code=200)
def session_login(request: AuthenticationRequest, response: Response):
  email = login(request)
  sid = uuid.uuid4().hex
  session_db[sid] = email
  response.set_cookie(
    key="sid",
    value=sid,
    path="/",
    samesite='lax',
    httponly=True,
    max_age=LONG_SESSION_LIFESPAN*60
  )
  return {'message': "session login succeed"}

@auth_router.delete("/session", status_code=204)
def session_logout(response: Response, sid: str | None = Cookie(default=None)):
  if sid not in session_db:
    return
  response.set_cookie(
    key="sid",
    value=sid,
    path="/",
    samesite='lax',
    httponly=True,
    max_age=0
  )
  del session_db[sid]
  return {'message': 'session logout succeed'}