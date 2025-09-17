from typing import Annotated

from fastapi import APIRouter, Depends, Cookie, Header, status

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from argon2 import PasswordHasher

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
  print(new_data)
  user_db.append(new_data)

  return UserResponse(**new_data)


@user_router.get("/me")
def get_user_info():
  pass
