"""CSV downloads that open correctly in Excel (UTF-8 with BOM)."""

import csv
import io
from collections.abc import Iterable, Sequence

from fastapi.responses import Response


def csv_response(filename: str, header: Sequence[str], rows: Iterable[Sequence]) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow(["" if value is None else str(value) for value in row])
    return Response(
        content=buffer.getvalue().encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
