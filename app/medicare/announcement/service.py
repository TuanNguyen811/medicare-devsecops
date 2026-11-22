"""Hospital announcements shown on the home page, written by administrators.

The body is limited rich text. It is cleaned with bleach against a strict allowlist
before it is stored, and only the cleaned HTML is ever rendered.
"""

import bleach
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.announcement.models import Announcement
from medicare.auth.models import User

MAX_TITLE = 200
MAX_BODY = 5000
HOME_LIMIT = 5

ALLOWED_TAGS = frozenset({
    "p", "br", "strong", "b", "em", "i", "u", "ul", "ol", "li", "blockquote", "a",
})
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}
ALLOWED_PROTOCOLS = frozenset({"http", "https", "mailto"})


class AnnouncementError(ValueError):
    """Invalid announcement data; the message is user-facing."""


def clean_body(raw: str) -> str:
    return bleach.clean(
        raw,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )


def create(db: Session, author: User, title: str, body: str) -> Announcement:
    title, body = title.strip(), body.strip()
    if not 1 <= len(title) <= MAX_TITLE:
        raise AnnouncementError(f"Tiêu đề: bắt buộc, tối đa {MAX_TITLE} ký tự")
    if not 1 <= len(body) <= MAX_BODY:
        raise AnnouncementError(f"Nội dung: bắt buộc, tối đa {MAX_BODY} ký tự")
    body_html = clean_body(body)
    if not body_html.strip():
        raise AnnouncementError("Nội dung: bắt buộc")
    announcement = Announcement(title=title, body_html=body_html, author_id=author.id)
    db.add(announcement)
    db.flush()
    return announcement


def latest(db: Session, limit: int = HOME_LIMIT) -> list[Announcement]:
    stmt = select(Announcement).order_by(Announcement.created_at.desc(),
                                         Announcement.id.desc()).limit(limit)
    return list(db.scalars(stmt).unique())


def delete(db: Session, announcement: Announcement) -> None:
    db.delete(announcement)
    db.flush()
