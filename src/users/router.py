from typing import Annotated

from fastapi import APIRouter, Depends, Cookie, Header, status

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db, User, find_user_index_by_email
from argon2 import PasswordHasher
from src.auth.router import auth_header, auth_cookie
from src.auth.router import verify_token, verify_session, session_login, get_email_by_token
from src.common.custom_exception import CustomException

user_router = APIRouter(prefix="/users", tags=["users"])
ph = PasswordHasher()


@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
  global user_db
  uid = len(user_db) + 1
  data = request.model_dump()

  new_data = {"user_id": uid} | data

  new_data["hashed_password"] = ph.hash(data["password"])
  user_db.append(User(**new_data))

  return UserResponse(**new_data)


@user_router.get("/me")
def get_user_info(sid: str | None = Depends(auth_cookie), token: str | None = Depends(auth_header)):
  if token:
    token = verify_token(token)
    user_email = get_email_by_token(token)
    id = find_user_index_by_email(user_email)
    return UserResponse(**user_db[id].model_dump())
  if sid:
    if sid in session_db:
      sid = verify_session(sid)
      id = find_user_index_by_email(session_db[sid])
      return UserResponse(**user_db[id].model_dump())
    raise CustomException(401, "ERR_006", "INVALID SESSION")
  raise CustomException(401, "ERR_009", "UNAUTHENTICATED")
