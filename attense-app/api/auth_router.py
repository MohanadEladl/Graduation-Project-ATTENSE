from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import session_store, user_store
from dependencies.auth import require_session

router = APIRouter(prefix="/api/auth")


class LoginRequest(BaseModel):
    username: str
    password: str


class LogoutRequest(BaseModel):
    token: str


@router.post("/login")
def login(body: LoginRequest):
    user = user_store.login_user(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    token = session_store.generate_session(user["username"], user["role"], user["company_id"])
    return {"token": token, "role": user["role"]}


@router.post("/logout")
def logout(body: LogoutRequest):
    session_store.delete_session(body.token)
    return {"message": "logged_out"}


@router.get("/me")
def me(session: dict = Depends(require_session)):
    return {"username": session["username"], "role": session["role"]}
