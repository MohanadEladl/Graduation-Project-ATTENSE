from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import company_store, hive_provisioner, user_store
from dependencies.auth import require_session

router = APIRouter(prefix="/api/company")

HIVE_KEY_ROLES = {"soc_manager", "soc_l1", "soc_l2"}


def _public_user(user: dict) -> dict:
    return {k: v for k, v in user.items() if k not in {"hashed_password", "hive_key"}}


class RegisterCompanyRequest(BaseModel):
    name: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str
    type: Optional[str] = None


class RegisterCompanyWithManagerRequest(BaseModel):
    company_name: str
    manager_username: str
    manager_email: str
    manager_password: str


@router.post("/register")
def register(body: RegisterCompanyRequest, session: dict = Depends(require_session)):
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can register a company")
    return company_store.create_company(body.name, created_by=session["username"])


@router.post("/register-with-manager")
def register_with_manager(body: RegisterCompanyWithManagerRequest):
    company = company_store.create_company(body.company_name, created_by=body.manager_username)
    try:
        manager = user_store.register_user(
            body.manager_username,
            body.manager_email,
            body.manager_password,
            "soc_manager",
            company_id=company["id"],
        )
    except ValueError as exc:
        company_store.delete_company(company["id"])
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"company": company, "manager": manager}


@router.get("/pending")
def list_pending(session: dict = Depends(require_session)):
    if session["role"] != "ciso":
        raise HTTPException(status_code=403, detail="Only ciso can list pending companies")
    return company_store.list_companies(status="pending")


@router.post("/{company_id}/confirm")
def confirm(company_id: str, session: dict = Depends(require_session)):
    if session["role"] != "ciso":
        raise HTTPException(status_code=403, detail="Only ciso can confirm a company")
    company = company_store.get_company(company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    if company["status"] == "active":
        return company
    try:
        hive_provisioner.create_org(company["name"])
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    manager = next(
        (
            user
            for user in user_store.get_users_by_company(company_id)
            if user["role"] == "soc_manager" and user["username"] == company["created_by"]
        ),
        None,
    )
    if manager is not None:
        try:
            hive_key = hive_provisioner.create_user_in_org(
                company["name"], manager["username"], attense_role="soc_manager"
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        user_store.set_hive_key(manager["id"], hive_key)

    return company_store.confirm_company(company_id)


@router.post("/{company_id}/users")
def create_user(
    company_id: str,
    body: CreateUserRequest,
    session: dict = Depends(require_session),
):
    if session["role"] != "soc_manager":
        raise HTTPException(status_code=403, detail="Only soc_manager can create users")

    company = company_store.get_company(company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    if company["status"] != "active":
        raise HTTPException(status_code=409, detail="Company must be confirmed first")
    if session.get("company_id") not in (None, company_id) and company.get("created_by") != session["username"]:
        raise HTTPException(status_code=403, detail="Cannot manage another company")

    hive_key = None
    try:
        # Validate all local constraints before creating a remote TheHive identity.
        if body.role not in user_store.VALID_ROLES:
            raise ValueError(
                f"Role must be one of: "
                f"{', '.join(sorted(user_store.VALID_ROLES))}"
            )
        if body.role == "red_team":
            if body.type not in user_store.RED_TEAM_TYPES:
                raise ValueError(
                    f"type is required for red_team and must be one of: "
                    f"{', '.join(sorted(user_store.RED_TEAM_TYPES))}"
                )
        elif body.type is not None:
            raise ValueError("type must be None for non-red-team roles")
        if user_store.username_exists(body.username):
            raise ValueError(f"Username already exists: {body.username}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if body.role in HIVE_KEY_ROLES:
        try:
            hive_key = hive_provisioner.create_user_in_org(
                company["name"],
                body.username,
                attense_role=body.role,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    try:
        user = user_store.register_user(
            body.username,
            body.email,
            body.password,
            body.role,
            company_id=company_id,
            hive_key=hive_key,
            type=body.type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return _public_user(user)


@router.get("/{company_id}/users")
def list_users(company_id: str, session: dict = Depends(require_session)):
    return [_public_user(user) for user in user_store.get_users_by_company(company_id)]
