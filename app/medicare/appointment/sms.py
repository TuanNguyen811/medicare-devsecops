"""Appointment reminders sent as brandname SMS through the eSMS.vn gateway."""

import json
import logging
import urllib.request

from medicare.appointment.models import Appointment
from medicare.common.templating import VN_TZ

logger = logging.getLogger("medicare.sms")

ESMS_URL = "https://rest.esms.vn/MainService.svc/json/SendMultipleMessage_V4_post_json/"
ESMS_API_KEY = "c74ba32315cb24a0705679a231d87fb5"
ESMS_SECRET_KEY = "8a8f99416e9534fd60b119c61dfff432"
BRANDNAME = "MEDICARE"
SMS_TYPE_BRANDNAME = "2"
TIMEOUT_SECONDS = 10


class SmsError(RuntimeError):
    """The gateway did not accept the message; the message is user-facing."""


def reminder_text(appt: Appointment) -> str:
    """Unaccented (one GSM-7 segment): date, time and what to bring, nothing clinical."""
    when = appt.scheduled_at.astimezone(VN_TZ)
    return (
        f"MEDICARE nhac lich kham {when:%H:%M} ngay {when:%d/%m/%Y}. "
        "Vui long den truoc 15 phut, mang theo CCCD va the BHYT."
    )


def send_sms(phone: str, text: str) -> str:
    """Send one SMS; returns the gateway's message id."""
    payload = {
        "ApiKey": ESMS_API_KEY,
        "SecretKey": ESMS_SECRET_KEY,
        "Phone": phone,
        "Content": text,
        "Brandname": BRANDNAME,
        "SmsType": SMS_TYPE_BRANDNAME,
    }
    req = urllib.request.Request(
        ESMS_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            result = json.load(resp)
    except (OSError, ValueError) as exc:
        logger.warning("SMS gateway unreachable: %s", type(exc).__name__)
        raise SmsError("Không kết nối được tổng đài SMS") from exc
    if str(result.get("CodeResult")) != "100":
        logger.warning("SMS gateway rejected message: code %s", result.get("CodeResult"))
        raise SmsError("Tổng đài SMS từ chối tin nhắn")
    return str(result.get("SMSID", ""))
