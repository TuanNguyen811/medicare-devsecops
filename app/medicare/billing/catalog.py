"""Billable services and their list prices in VND.

Invoice lines only ever take their unit price from this catalog (R-17).
"""

from decimal import Decimal

SERVICES: dict[str, tuple[str, Decimal]] = {
    "XN-CTM": ("Xét nghiệm công thức máu", Decimal(90000)),
    "XN-SHM": ("Xét nghiệm sinh hóa máu", Decimal(150000)),
    "XN-NT": ("Xét nghiệm nước tiểu", Decimal(45000)),
    "XQ-NGUC": ("Chụp X-quang ngực thẳng", Decimal(120000)),
    "SA-BUNG": ("Siêu âm ổ bụng", Decimal(180000)),
    "DIEN-TIM": ("Điện tim thường", Decimal(70000)),
    "THAY-BANG": ("Thay băng vết thương", Decimal(55000)),
    "GIUONG-NOI": ("Ngày giường bệnh nội khoa", Decimal(250000)),
}
