from typing import Optional

from core.db import connection, int_id

# Shared holding company for auto-created exercise rooms (attacks launched
# without a SOC-Manager-created room). Blue Team has global room visibility, so
# rooms under this company are seen by everyone regardless of their own org.
EXERCISE_COMPANY_NAME = "ATTENSE Exercise"


def _company_from_row(row: dict | None) -> Optional[dict]:
    if row is None:
        return None
    return {
        "id": str(row["company_id"]),
        "name": row["name"],
        "status": row.get("status", "pending"),
        "created_by": row.get("created_by"),
    }


def create_company(name: str, created_by: str) -> dict:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            INSERT INTO "Company" (name, status, created_by)
            VALUES (%s, 'pending', %s)
            ON CONFLICT (name) DO UPDATE
            SET name = EXCLUDED.name
            RETURNING company_id, name, status, created_by
            ''',
            (name, created_by),
        )
        return _company_from_row(cur.fetchone())


def ensure_exercise_company() -> dict:
    """Return the shared, active exercise company, creating it if needed.

    Auto-created attack rooms are parented here so they exist independently of
    any real org. Idempotent: safe to call on every attack event.
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            INSERT INTO "Company" (name, status, created_by)
            VALUES (%s, 'active', 'system')
            ON CONFLICT (name) DO UPDATE
            SET status = 'active'
            RETURNING company_id, name, status, created_by
            ''',
            (EXERCISE_COMPANY_NAME,),
        )
        return _company_from_row(cur.fetchone())


def get_company(company_id: str) -> Optional[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            'SELECT company_id, name, status, created_by FROM "Company" WHERE company_id = %s',
            (int_id(company_id, "company_id"),),
        )
        return _company_from_row(cur.fetchone())


def confirm_company(company_id: str) -> Optional[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            UPDATE "Company"
            SET status = 'active'
            WHERE company_id = %s
            RETURNING company_id, name, status, created_by
            ''',
            (int_id(company_id, "company_id"),),
        )
        return _company_from_row(cur.fetchone())


def delete_company(company_id: str) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute('DELETE FROM "Company" WHERE company_id = %s', (int_id(company_id, "company_id"),))


def list_companies(status: Optional[str] = None) -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        if status is None:
            cur.execute('SELECT company_id, name, status, created_by FROM "Company" ORDER BY company_id')
        else:
            cur.execute(
                'SELECT company_id, name, status, created_by FROM "Company" WHERE status = %s ORDER BY company_id',
                (status,),
            )
        return [_company_from_row(row) for row in cur.fetchall()]