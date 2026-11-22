"""Nightly housekeeping of the audit table.

Every page load and API call on a record writes a VIEW_RECORD row, so a doctor keeping a
chart open on the ward screen produces hundreds of identical rows per shift. The first
view of a burst is enough to know who looked at the record and when.

Usage (CronJob): python -m medicare.audit.maintenance [--window-minutes 30]
"""

import argparse
import logging
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from medicare.audit.models import AuditLog
from medicare.audit.service import VIEW_RECORD
from medicare.common.logs import configure_logging
from medicare.config import Settings
from medicare.db import create_db

logger = logging.getLogger("medicare.audit.maintenance")

DEFAULT_WINDOW = timedelta(minutes=30)


def compact_repeated_views(db: Session, window: timedelta = DEFAULT_WINDOW) -> int:
    """Delete VIEW_RECORD rows that repeat the same actor's view of the same record within
    `window` of their previous view. Returns the number of rows removed."""
    previous_at = func.lag(AuditLog.at).over(
        partition_by=(AuditLog.actor_id, AuditLog.entity_type, AuditLog.entity_id),
        order_by=(AuditLog.at, AuditLog.id),
    )
    views = (
        select(AuditLog.id, (AuditLog.at - previous_at).label("gap"))
        .where(AuditLog.action == VIEW_RECORD)
        .subquery()
    )
    repeated = select(views.c.id).where(views.c.gap <= window)
    result = db.execute(delete(AuditLog).where(AuditLog.id.in_(repeated)))
    return result.rowcount


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--window-minutes", type=int, default=30)
    args = parser.parse_args(argv)
    settings = Settings()
    configure_logging(settings.log_level)
    engine, session_factory = create_db(settings.database_url)
    try:
        with session_factory() as db, db.begin():
            removed = compact_repeated_views(db, timedelta(minutes=args.window_minutes))
        logger.info("audit.compact", extra={"removed": removed})
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
