"""BHYT card check through the lookup tool BHXH ships to hospitals.

The tool (`tra-cuu-the`) queries the national insurance portal and prints one JSON
object on stdout. It is installed on the application server; its path comes from the
BHYT_CLI setting.
"""

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import date

from medicare.validators import is_valid_insurance_number

TIMEOUT_SECONDS = 15
_DATE_VN = re.compile(r"[0-9]{2}/[0-9]{2}/[0-9]{4}")
RESULT_MESSAGES = {
    "000": "Thẻ BHYT còn giá trị sử dụng",
    "001": "Thẻ BHYT đã hết hạn sử dụng",
    "002": "Họ tên hoặc ngày sinh không khớp với thông tin thẻ",
    "003": "Thẻ BHYT không tồn tại hoặc đã bị thu hồi",
}


class InsuranceCheckError(Exception):
    """The check could not be completed; the message is user-facing."""


@dataclass(frozen=True)
class CheckResult:
    message: str
    valid: bool
    valid_until: str | None


def build_command(executable: str, card: str, full_name: str, date_of_birth: date) -> list[str]:
    """Argument vector for the tool. Every value travels as `--name=value`, so none of
    them can be read as a separate option."""
    if not is_valid_insurance_number(card):
        raise InsuranceCheckError("Mã thẻ BHYT không đúng định dạng")
    name = " ".join(full_name.split())
    if not (1 <= len(name) <= 100 and name.isprintable()):
        raise InsuranceCheckError("Họ tên bệnh nhân không hợp lệ để tra cứu")
    return [
        executable,
        "--json",
        f"--ma-the={card}",
        f"--ho-ten={name}",
        f"--ngay-sinh={date_of_birth:%d/%m/%Y}",
    ]


def check_card(executable: str, card: str, full_name: str, date_of_birth: date) -> CheckResult:
    command = build_command(executable, card, full_name, date_of_birth)
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise InsuranceCheckError("Cổng BHYT không phản hồi, vui lòng thử lại sau") from None
    except OSError:
        raise InsuranceCheckError("Máy chủ chưa sẵn sàng công cụ tra cứu BHYT") from None
    if proc.returncode != 0:
        raise InsuranceCheckError("Tra cứu thẻ BHYT không thành công, vui lòng thử lại sau")
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        raise InsuranceCheckError("Cổng BHYT trả về kết quả không đọc được") from None
    code = data.get("ma_ket_qua") if isinstance(data, dict) else None
    message = RESULT_MESSAGES.get(code) if isinstance(code, str) else None
    if message is None:
        raise InsuranceCheckError("Cổng BHYT trả về kết quả không xác định")
    until = data.get("den_ngay")
    valid_until = until if isinstance(until, str) and _DATE_VN.fullmatch(until) else None
    return CheckResult(message=message, valid=code == "000", valid_until=valid_until)
