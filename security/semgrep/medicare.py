# Test targets for security/semgrep/medicare.yml (run: semgrep --test security/semgrep)
from fastapi import APIRouter
from markupsafe import Markup
from sqlalchemy import text

from medicare.common.ids import ObjectId

router = APIRouter()


def search(db, q, order):
    # ruleid: medicare.sqlalchemy-text-fstring
    db.execute(text(f"SELECT * FROM patients WHERE full_name LIKE '%{q}%'"))
    # ruleid: medicare.sqlalchemy-text-fstring
    db.execute(text("SELECT * FROM patients ORDER BY " + order))
    # ruleid: medicare.sqlalchemy-text-fstring
    db.execute(text("SELECT * FROM patients WHERE code = '{}'".format(q)))
    # ok: medicare.sqlalchemy-text-fstring
    db.execute(text("SELECT * FROM patients WHERE code = :code"), {"code": q})
    # ok: medicare.sqlalchemy-text-fstring
    db.execute(text("SELECT now()"))


def render_note(note):
    # ruleid: medicare.jinja-safe-filter
    return Markup(note)


# ruleid: medicare.route-int-path-param
@router.get("/patients/{patient_id}")
def unsafe_detail(patient_id: int):
    return patient_id


# ok: medicare.route-int-path-param
@router.get("/records/{record_id}")
def safe_detail(record_id: ObjectId):
    return record_id


# ok: medicare.route-int-path-param
@router.get("/patients")
def listing(page: int = 1):
    return page
