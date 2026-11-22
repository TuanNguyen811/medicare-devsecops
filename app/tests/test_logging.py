import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from medicare.audit.maintenance import compact_repeated_views
from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.common.logs import JsonFormatter, configure_logging
from tests.conftest import login
from tests.factories import make_department, make_patient, make_record, make_user

T0 = datetime(2026, 11, 2, 8, 0, tzinfo=UTC)


def test_json_formatter_puts_extra_fields_at_top_level():
    record = logging.LogRecord("medicare.test", logging.INFO, __file__, 1, "job.done", None, None)
    record.removed = 3
    entry = json.loads(JsonFormatter().format(record))
    assert entry["msg"] == "job.done" and entry["level"] == "INFO"
    assert entry["logger"] == "medicare.test" and entry["removed"] == 3
    assert entry["ts"].endswith("+00:00")


def test_configure_logging_is_idempotent():
    configure_logging("INFO")
    configure_logging("INFO")
    handlers = logging.getLogger("medicare").handlers
    assert len([h for h in handlers if isinstance(h.formatter, JsonFormatter)]) == 1


def test_record_view_emits_event(client, db, caplog):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    record = make_record(db, make_patient(db, department=dept, attending=doc), doc)
    login(client, doc)
    caplog.set_level(logging.INFO, logger="medicare")
    assert client.get(f"/records/{record.id}").status_code == 200
    events = [r for r in caplog.records if r.getMessage() == "record.view"]
    assert len(events) == 1
    assert events[0].record_id == record.id and events[0].user_id == doc.id


def _view(db, actor, record_id, at, action="VIEW_RECORD"):
    row = AuditLog(actor_id=actor.id, action=action, entity_type="record",
                   entity_id=record_id, ip="10.0.0.1", at=at)
    db.add(row)
    db.flush()
    return row


def test_compaction_keeps_first_view_of_each_burst(db):
    doc, nurse = make_user(db, Role.DOCTOR), make_user(db, Role.NURSE)
    first = _view(db, doc, 501, T0)
    _view(db, doc, 501, T0 + timedelta(minutes=5))
    _view(db, doc, 501, T0 + timedelta(minutes=20))
    later = _view(db, doc, 501, T0 + timedelta(hours=3))
    other_record = _view(db, doc, 502, T0 + timedelta(minutes=1))
    other_actor = _view(db, nurse, 501, T0 + timedelta(minutes=2))
    update = _view(db, doc, 501, T0 + timedelta(minutes=6), action="UPDATE_RECORD")
    assert compact_repeated_views(db, timedelta(minutes=30)) == 2
    kept = set(db.scalars(select(AuditLog.id).where(AuditLog.entity_id.in_([501, 502]))))
    assert kept == {first.id, later.id, other_record.id, other_actor.id, update.id}
