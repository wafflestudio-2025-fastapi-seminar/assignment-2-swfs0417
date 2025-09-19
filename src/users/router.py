from typing import Annotated

from fastapi import APIRouter, Depends, Cookie, Header, status

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from argon2 import PasswordHasher
from src.auth.router import verify_token, session_login
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
  del new_data["password"]
  user_db.append(new_data)

  return UserResponse(**new_data)


@user_router.get("/me")
def get_user_info(sid=Cookie(None), access_token: str | None = Header(default=None)):
  if sid:
    if sid in session_db:
      for user in user_db:
        if user['email'] == session_db[sid]:
          return UserResponse(**user)
    return CustomException(401, "ERR_006", "INVALID SESSION")
  if access_token:
    user_email, payload, token = verify_token(access_token)
    for user in user_db:
        if user['email'] == user_email:
          return UserResponse(**user)
