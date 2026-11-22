"""Outgoing mail.

SMTP is not wired up yet: messages are kept in an in-memory outbox and nothing leaves
the process.
"""

import logging
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger("medicare.mail")

OUTBOX_SIZE = 200


@dataclass(frozen=True)
class Mail:
    to: str
    subject: str
    body: str


outbox: deque[Mail] = deque(maxlen=OUTBOX_SIZE)


def send_mail(to: str, subject: str, body: str) -> None:
    outbox.append(Mail(to=to, subject=subject, body=body))
    # Subject only: the address is personal data and the body may carry a reset link (R-10).
    logger.info("Queued mail: %s", subject)
