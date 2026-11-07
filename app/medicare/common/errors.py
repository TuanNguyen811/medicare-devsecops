import logging
import traceback

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.exc import DataError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from medicare.common.auth import LoginRequired
from medicare.common.templating import render

logger = logging.getLogger("medicare.errors")

GENERIC_500 = "Đã có lỗi xảy ra. Vui lòng thử lại sau."
_MESSAGES = {
    400: "Dữ liệu gửi lên không hợp lệ.",
    403: "Bạn không có quyền thực hiện thao tác này.",
    404: "Không tìm thấy nội dung yêu cầu.",
    405: "Thao tác không được hỗ trợ.",
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


async def _validation_handler(request: Request, exc: Exception) -> Response:
    """Malformed request parameters. Never echoes the input back.

    An invalid object id in the path can never exist, so it gets exactly the
    missing-object response (R-15); anything else is a plain 400.
    """
    if not isinstance(exc, RequestValidationError):
        raise TypeError(type(exc).__name__)
    if any(err.get("loc", ("",))[0] == "path" for err in exc.errors()):
        return await _http_exception_handler(request, NotFound())
    return await _http_exception_handler(
        request, StarletteHTTPException(status_code=400, detail="Bad Request")
    )


async def _data_error_handler(request: Request, exc: Exception) -> Response:
    """Safety net: input the database rejects (e.g. NUL bytes) is a 400, not a 500."""
    logger.warning("Rejected request data: %s", type(exc).__name__)
    return await _http_exception_handler(
        request, StarletteHTTPException(status_code=400, detail="Bad Request")
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(LoginRequired, _login_required_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
    app.add_exception_handler(DataError, _data_error_handler)


class CatchAllErrorsMiddleware:
    """Turn any unhandled exception into the generic 500 response without re-raising.

    Starlette's ServerErrorMiddleware re-raises after its handler runs, so uvicorn would
    log str(exc), which can contain PII. Sitting inside it, this middleware swallows the
    exception after logging only its class name and frame locations.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            response = await _unhandled_handler(Request(scope, receive), exc)
            if not started:
                await response(scope, receive, send)
