from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import company_store, room_manager, session_store, user_store
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




class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    team: str
    role: str | None = None
    company_name: str | None = None


ROLE_ALIASES = {
    "red": "red_team",
    "red_team": "red_team",
    "ciso": "ciso",
    "soc": "soc_l1",
    "soc_l1": "soc_l1",
    "analyst": "soc_l1",
    "ir": "soc_l2",
    "soc_l2": "soc_l2",
    "th": "soc_l1",
    "threat_hunter": "soc_l1",
    "manager": "soc_manager",
    "soc_manager": "soc_manager",
}


def _registration_username(email: str) -> str:
    return email.strip().lower()


def _registration_role(team: str, role: str | None) -> str:
    key = (role or team).strip().lower()
    if team.strip().lower() == "red":
        return "red_team"
    return ROLE_ALIASES.get(key, key)


@router.post("/login")
def login(body: LoginRequest):
    user = user_store.login_user(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    token = session_store.generate_session(user["username"], user["role"], user["company_id"])
    return {"token": token, "role": user["role"]}


@router.post("/register")
def register(body: RegisterRequest):
    email = body.email.strip().lower()
    username = _registration_username(email)
    role = _registration_role(body.team, body.role)
    if role not in user_store.VALID_ROLES:
        raise HTTPException(status_code=400, detail="invalid_role")
    if user_store.account_exists(username, email):
        raise HTTPException(status_code=400, detail="Could not create account. Try a different email or password.")

    company_id = None
    if role != "ciso":
        company_name = (body.company_name or "Independent").strip() or "Independent"
        company = company_store.create_company(company_name, created_by=username)
        company_id = company["id"]

    red_type = None
    if role == "red_team":
        red_type = "expert" if (body.role or "").strip().lower() in {"rtlead", "maldev"} else "intermediate"

    try:
        user = user_store.register_user(
            username,
            email,
            body.password,
            role,
            company_id=company_id,
            type=red_type,
        )
    except ValueError as exc:
        detail = "Could not create account. Try a different email or password." if "already exists" in str(exc).lower() else str(exc)
        raise HTTPException(status_code=400, detail=detail) from exc
    return {"username": user["username"], "email": email, "role": user["role"]}

@router.post("/logout")
def logout(body: LogoutRequest):
    session_store.delete_session(body.token)
    return {"message": "logged_out"}


@router.get("/me")
def me(session: dict = Depends(require_session)):
    response = {"username": session["username"], "role": session["role"]}
    user = user_store.get_user_by_username(session["username"])
    if user is not None:
        # Real identity for the red-team app's Settings → Account panel. There is
        # no separate full-name column for red_team users, so display_name is the
        # username; both come from the already-fetched user dict (no new query).
        response["email"] = user.get("email")
        response["display_name"] = user.get("username")
        response["type"] = user.get("type")
        if session["role"] in user_store.HIVE_KEY_ROLES:
            response["hive_key"] = user.get("hive_key")
        if session["role"] == "red_team":
            room = None
            active_room_id = user.get("active_room_id")
            if active_room_id:
                room = room_manager.get_room_if_member(active_room_id, session["username"])
            if room is None:
                room = room_manager.find_room_for_red_team_member(session["username"])
            if room is not None:
                response["room_id"] = room["room_id"]
                response["incident_id"] = room.get("incident_id")
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
