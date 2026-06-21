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


class BootstrapCisoRequest(BaseModel):
    username: str
    email: str
    password: str


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
    response = {"username": session["username"], "role": session["role"]}
    user = user_store.get_user_by_username(session["username"])
    if user is not None:
        response["type"] = user.get("type")
        if session["role"] in user_store.HIVE_KEY_ROLES:
            response["hive_key"] = user.get("hive_key")
    return response


@router.post("/bootstrap-ciso")
def bootstrap_ciso(body: BootstrapCisoRequest):
    if user_store.ciso_exists():
        raise HTTPException(status_code=403, detail="CISO already exists")
    try:
        user = user_store.register_user(
            body.username, body.email, body.password, "ciso", company_id=None
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return user
