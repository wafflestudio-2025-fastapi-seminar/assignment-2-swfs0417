from fastapi import APIRouter
from fastapi import Depends, Cookie, Header
from fastapi.security import APIKeyCookie, APIKeyHeader
from fastapi.responses import Response

from src.common.database import blocked_token_db, session_db, user_db, find_user_index_by_email
from src.auth.schemas import AuthenticationRequest, Token
from src.common.custom_exception import CustomException
from src.users.errors import InvalidAccountException
import uuid

from argon2 import PasswordHasher, exceptions
from authlib.jose import jwt
import authlib.jose.errors as JWTerror
from datetime import datetime, timedelta

ph = PasswordHasher()

auth_router = APIRouter(prefix="/auth", tags=["auth"])

auth_header = APIKeyHeader(name = "Authorization", auto_error=False)
auth_cookie = APIKeyCookie(name = "sid", auto_error=False)

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60
SECRET_KEY = "3a8b9b1b11f11eabb7bd5d9c10d9ae8fc7ec47a6403fde2436c4168ba384157e"
JWT_HEADER = {"alg": "HS256", "typ": "JWT"}


def new_token(user_email: str) -> Token:
  '''new JWT token with given email'''
  payload_acc = {"sub": user_email, "exp": (datetime.now() + timedelta(minutes=SHORT_SESSION_LIFESPAN))}
  payload_ref = {"sub": user_email, "exp": (datetime.now() + timedelta(minutes=LONG_SESSION_LIFESPAN))}

  token = {
    "access_token": jwt.encode(JWT_HEADER, payload_acc, SECRET_KEY),
    "refresh_token": jwt.encode(JWT_HEADER, payload_ref, SECRET_KEY),
  }
  return Token(**token)

def verify_token(Authorization: str = Depends(auth_header)) -> str:
  '''verify token and return token'''
  if not Authorization:
    raise CustomException(401, "ERR_009", "UNAUTHENTICATED")
  if Authorization.split(" ")[0] != "Bearer":
    raise CustomException(400, "ERR_007", "BAD AUTHORIZATION HEADER")
  token = Authorization.split(" ")[1]
  if (token in blocked_token_db):
    raise CustomException(401, "ERR_008", "INVALID TOKEN")
  try:
    # print(token)
    payload = jwt.decode(token, SECRET_KEY)
    # print(payload.get('exp'), datetime.now().timestamp())
    if payload.get('exp') < datetime.now().timestamp():
      raise CustomException(401, "ERR_008", "INVALID TOKEN")
  except (JWTerror.JoseError):
    raise CustomException(401, "ERR_008", "INVALID TOKEN")
  return token

def verify_session(sid: str = Depends(auth_cookie)) -> str:
  if sid not in session_db:
    raise CustomException(401, "ERR_006", "INVALID SESSION")
  try:
    find_user_index_by_email(session_db[sid])
  except InvalidAccountException:
    raise CustomException(401, "ERR_006", "INVALID SESSION")

def login(idpw: AuthenticationRequest) -> str:
  user = user_db[find_user_index_by_email(idpw.email)]
  ph.verify(user.hashed_password, idpw.password)
  return user.email
  

# def verify_token(token: )


@auth_router.post("/token")
def token_login(request = Depends(login)) -> Token:
  return new_token(request)


@auth_router.post("/token/refresh")
def refresh_token(token: str = Depends(verify_token)) -> Token:
  payload = jwt.decode(token, SECRET_KEY)
  user_email = payload.get('sub')
  try:
    find_user_index_by_email(user_email)
    blocked_token_db[token] = payload.get('exp')
    return new_token(user_email)
  except InvalidAccountException:
    raise CustomException(401, "ERR_008", "INVALID TOKEN")

@auth_router.delete("/token")
def delete_token(token: str = Depends(verify_token)):
  payload = jwt.decode(token, SECRET_KEY)
  user_email = payload.get('sub')
  try:
    find_user_index_by_email(user_email)
    blocked_token_db[token] = payload.get('exp')
    return Response(status_code=204)
  except InvalidAccountException:
    raise CustomException(401, "ERR_008", "INVALID TOKEN")


@auth_router.post("/session", status_code=200)
def session_login(response: Response, email = Depends(login)):
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
  return

@auth_router.delete("/session", status_code=204)
def session_logout(response: Response, sid: str | None = Cookie(default=None)):
  response.set_cookie(
    key="sid",
    max_age=0
  )
  if sid in session_db:
    del session_db[sid]
  return {'message': 'session logout succeed'}