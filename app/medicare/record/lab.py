"""Lab reports published by the laboratory system (LIS) and attached to a visit record.

The LIS publishes each finished report at a URL; the doctor pastes that URL and the
server downloads the report once and keeps a copy, so it stays readable after the LIS
purges old reports.
"""

import urllib.request
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare import policy
from medicare.audit import service as audit
from medicare.auth.models import User
from medicare.common import metrics
from medicare.common.errors import NotFound
from medicare.patient.models import Patient
from medicare.record.models import LabResult, MedicalRecord

ENTITY = "record"
MAX_BYTES = 10 * 1024 * 1024
FETCH_TIMEOUT = 15
ALLOWED_TYPES = {"application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg"}


class LabResultError(ValueError):
    """The report could not be attached; the message is user-facing."""


def download(url: str) -> tuple[bytes, str]:
    """Fetch a published report; returns (content, content type)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LabResultError("Đường dẫn phải bắt đầu bằng http:// hoặc https://")
    request = urllib.request.Request(url, headers={"User-Agent": "MediCare-HMS"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as resp:
            content_type = resp.headers.get_content_type()
            content = resp.read(MAX_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise LabResultError("Không tải được kết quả từ đường dẫn này") from exc
    if content_type not in ALLOWED_TYPES:
        raise LabResultError("Kết quả phải là file PDF hoặc ảnh PNG/JPEG")
    if len(content) > MAX_BYTES:
        raise LabResultError("File kết quả vượt quá 10 MB")
    return content, content_type


def attach(
    db: Session, user: User, record: MedicalRecord, title: str, url: str, ip: str | None
) -> LabResult:
    """Download the report at `url` and attach it to `record` (caller checked R-02)."""
    title, url = title.strip(), url.strip()
    if not 1 <= len(title) <= 200:
        raise LabResultError("Tên xét nghiệm: bắt buộc, tối đa 200 ký tự")
    if len(url) > 500:
        raise LabResultError("Đường dẫn quá dài")
    content, content_type = download(url)
    result = LabResult(record_id=record.id, title=title, source_url=url,
                       content_type=content_type, content=content, created_by_id=user.id)
    db.add(result)
    db.flush()
    audit.log_access(db, user, audit.ATTACH_LAB_RESULT, ENTITY, record.id, ip)
    return result


def list_for_record(db: Session, record_id: int) -> list:
    """Id, title and time of each report; the file content is not loaded."""
    stmt = (
        select(LabResult.id, LabResult.title, LabResult.created_at)
        .where(LabResult.record_id == record_id)
        .order_by(LabResult.created_at, LabResult.id)
    )
    return list(db.execute(stmt))


def get_for(db: Session, user: User, result_id: int, ip: str | None) -> LabResult:
    """A report is part of the record: same visibility and auditing (R-02, R-05, R-15)."""
    result = db.get(LabResult, result_id)
    if result is None:
        raise NotFound
    record = db.get(MedicalRecord, result.record_id)
    if not policy.can_view_record(user, db.get(Patient, record.patient_id)):
        metrics.authz_denied("record")
        raise NotFound
    audit.log_access(db, user, audit.VIEW_LAB_RESULT, ENTITY, record.id, ip)
    return result
