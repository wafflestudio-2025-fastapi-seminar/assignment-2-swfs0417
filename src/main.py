from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from src.users.errors import CustomException
import argon2


from tests.util import get_all_src_py_files_hash
from src.api import api_router

app = FastAPI()
ph = argon2.PasswordHasher()

app.include_router(api_router)

@app.exception_handler(RequestValidationError)
def handle_request_validation_error(request, exc):
    return JSONResponse(
      content = {
        "error_code": "ERR_001",
        "error_msg": "MISSING VALUE"
      },
      status_code=422
    )
  
@app.exception_handler(CustomException)
def handle_custom_error(request, exc: CustomException):
    return JSONResponse(
      content = {
        "error_code": exc.error_code,
        "error_msg": exc.error_message
      },
      status_code=exc.status_code
    )

@app.exception_handler(argon2.exceptions.VerifyMismatchError)
def handle_verify_mismatch_error(request, exc: argon2.exceptions.VerifyMismatchError):
  return JSONResponse(
      content = {
        "error_code": "ERR_010",
        "error_msg": "INVALID ACCOUNT"
      },
      status_code=401
    )

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }