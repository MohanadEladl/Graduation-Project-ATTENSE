from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import company_store, hive_provisioner, user_store
from dependencies.auth import require_session

router = APIRouter(prefix="/api/company")

HIVE_KEY_ROLES = {"soc_manager", "soc_l1", "soc_l2"}


class RegisterCompanyRequest(BaseModel):
    name: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str


@router.post("/register")
def register(body: RegisterCompanyRequest, session: dict = Depends(require_session)):
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can register a company")
    return company_store.create_company(body.name, created_by=session["username"])


@router.post("/{company_id}/users")
def create_user(
    company_id: str,
    body: CreateUserRequest,
    session: dict = Depends(require_session),
):
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can create users")

    try:
        user = user_store.register_user(
            body.username, body.email, body.password, body.role, company_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if body.role in HIVE_KEY_ROLES:
        company = company_store.get_company(company_id)
        if company is None:
            raise HTTPException(status_code=404, detail="Company not found")
        try:
            hive_key = hive_provisioner.create_user_in_org(company["name"], body.username)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        user = user_store.set_hive_key(user["id"], hive_key)
        user = {k: v for k, v in user.items() if k != "hashed_password"}

    return user


@router.get("/{company_id}/users")
def list_users(company_id: str, session: dict = Depends(require_session)):
    return user_store.get_users_by_company(company_id)
