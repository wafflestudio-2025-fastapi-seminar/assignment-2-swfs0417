from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from common.database import blocked_token_db, session_db, user_db

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    global user_db
    uid = len(user_db) + 1
    data = request.model_dump()
    
    user_db.append({"user_id": uid} + data)

@user_router.get("/me")
def get_user_info():
    pass