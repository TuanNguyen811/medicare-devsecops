import logging
import traceback

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from medicare.common.auth import LoginRequired
from medicare.common.templating import render

logger = logging.getLogger("medicare.errors")

GENERIC_500 = "Đã có lỗi xảy ra. Vui lòng thử lại sau."
_MESSAGES = {
    403: "Bạn không có quyền thực hiện thao tác này.",
    404: "Không tìm thấy nội dung yêu cầu.",
}


class NotFound(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=404, detail="Not Found")


class Conflict(HTTPException):
    def __init__(self, detail: str = "Conflict") -> None:
        super().__init__(status_code=409, detail=detail)


def _is_api(request: Request) -> bool:
    return request.url.path.startswith("/api/")


async def _http_exception_handler(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, StarletteHTTPException)
    if _is_api(request):
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )
    message = exc.detail if exc.status_code == 409 else _MESSAGES.get(exc.status_code, GENERIC_500)
    return render(
        request,
        "error.html",
        {"status": exc.status_code, "message": message},
        status_code=exc.status_code,
    )


async def _login_required_handler(request: Request, exc: Exception) -> Response:
    if _is_api(request):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


async def _unhandled_handler(request: Request, exc: Exception) -> Response:
    # Log only the class name and file:line:function of each frame: exception messages can
    # carry PII (e.g. database DETAIL lines) and source lines may echo literals, so neither
    # str(exc), source text nor request data reach the log.
    frames = "\n".join(
        f"  {f.filename}:{f.lineno} in {f.name}" for f in traceback.extract_tb(exc.__traceback__)
    )
    logger.error("Unhandled %s\n%s", type(exc).__name__, frames)
    if _is_api(request):
        return JSONResponse({"detail": "Internal Server Error"}, status_code=500)
    request.state.current_user = None  # the error page must not touch the session or the DB
    return render(
        request, "error.html", {"status": 500, "message": GENERIC_500}, status_code=500
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(LoginRequired, _login_required_handler)
    app.add_exception_handler(Exception, _unhandled_handler)
