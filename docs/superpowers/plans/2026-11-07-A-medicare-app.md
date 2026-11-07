# Kế hoạch A: Ứng dụng MediCare HMS (bản sạch)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xây dựng hệ thống quản lý bệnh viện MediCare HMS: viết đúng chuẩn bảo mật, có kiểm thử phân quyền, chạy được bằng `docker compose`. Đây là ứng dụng mục tiêu cho pipeline DevSecOps và AI Agent.

**Architecture:** FastAPI render HTML bằng Jinja2, cộng một vài API JSON chỉ đọc dưới `/api/v1`. SQLAlchemy 2 (đồng bộ) trên PostgreSQL, migration bằng Alembic. Xác thực bằng session cookie có ký (Starlette `SessionMiddleware`) và CSRF token. Phân quyền theo vai trò ở route (`require_roles`), phân quyền theo đối tượng tập trung ở `medicare/policy.py`. Code chia theo module tính năng.

**Tech Stack:** Python 3.12, uv, FastAPI, Jinja2, SQLAlchemy 2, psycopg 3, Alembic, argon2-cffi, pydantic-settings, Faker; pytest, httpx, testcontainers[postgres], ruff.

**Spec:** `docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md` (mục 2). Hợp đồng giao tiếp: `docs/superpowers/plans/2026-11-07-00-roadmap.md` (Hợp đồng 1).

## Global Constraints

- Python `>=3.12,<3.13`. Project `uv` nằm ở `app/`, mọi lệnh chạy từ `app/`: `uv run pytest`, `uv run ruff check`.
- PostgreSQL 16 (image `postgres:16-alpine`) cho cả test (Testcontainers) lẫn compose.
- Không viết cứng secret. `SECRET_KEY`, `DATABASE_URL`, `DEMO_PASSWORD` chỉ đọc từ biến môi trường. Repo chỉ có `.env.example` với giá trị giả `change-me`.
- Mọi truy vấn qua ORM hoặc `text()` có bind parameter. Không nối chuỗi vào SQL.
- Jinja2 bật autoescape. **Cấm** `|safe`, `Markup(...)` trên dữ liệu người dùng, `pickle`, `yaml.load`, `subprocess(..., shell=True)`, `eval`/`exec`.
- **Cấm** comment chặn cảnh báo (`# nosec`, `# nosemgrep`, `# noqa: S…`).
- Phân quyền theo đối tượng chỉ qua hàm `can_*` trong `medicare/policy.py`. Docstring mỗi hàm ghi mã `R-xx`.
- Truy cập đối tượng không có quyền hoặc không tồn tại → **404** (tránh dò ID). Sai vai trò ở route → **403**. Thiếu hoặc sai CSRF → **403**. Chưa đăng nhập → 303 về `/login` với trang HTML, 401 với `/api/v1`.
- Không ghi PII vào log: CCCD, mã BHYT, chẩn đoán, ghi chú bệnh án, mật khẩu.
- Lỗi không bắt được → trang lỗi chung "Đã có lỗi xảy ra. Vui lòng thử lại sau." với mã 500, không có stack trace.
- Giao diện tiếng Việt. Tên biến, hàm và bảng bằng tiếng Anh.
- Mật khẩu dùng chung cho mọi user trong test: `Passw0rd!` (hằng `TEST_PASSWORD` trong `tests/factories.py`).

## Review Focus

1. **Dò ID đối tượng:** ID không tồn tại và ID có thật nhưng không có quyền phải trả về **cùng** mã 404 với cùng nội dung → test ở Task 5 (`test_patient_detail_forbidden_and_missing_are_identical`).
2. **User bị vô hiệu hóa khi đang còn session:** request kế tiếp phải bị coi như chưa đăng nhập → test ở Task 3 (`test_deactivated_user_session_is_rejected`).
3. **Dữ liệu form sai định dạng** (CCCD không đủ 12 số, mã BHYT sai, ngày hẹn trong quá khứ): hiển thị lại form với mã 400 và thông báo lỗi, không trả 500 → test ở Task 5 và Task 6.
4. **Hai người đặt trùng giờ cùng một bác sĩ cùng lúc:** chặn bằng ràng buộc ở cơ sở dữ liệu, trả 409, không trả 500 → test ở Task 6 (`test_double_booking_rejected_at_db_level`).
5. **Exception không lường trước:** không lộ stack trace hay nội dung exception, không ghi PII vào log → test ở Task 3 (`test_unhandled_error_is_generic`) và Task 7 (`test_record_creation_does_not_log_pii`).

---

## Cấu trúc file

```
app/
├── pyproject.toml, uv.lock, alembic.ini, .env.example
├── medicare/
│   ├── main.py              # create_app()
│   ├── config.py            # Settings
│   ├── db.py                # Base, engine, get_db
│   ├── policy.py            # các hàm can_* (R-xx)
│   ├── validators.py        # CCCD, BHYT, mask()
│   ├── seed.py              # python -m medicare.seed
│   ├── common/
│   │   ├── auth.py          # get_current_user, require_roles, đăng nhập/khóa tài khoản
│   │   ├── passwords.py     # hash_password, verify_password (Argon2)
│   │   ├── csrf.py          # get_csrf_token, verify_csrf
│   │   ├── errors.py        # NotFound, Conflict, exception handler
│   │   └── templating.py    # templates (Jinja2Templates), render()
│   ├── auth/       {models.py, router.py, admin_router.py}
│   ├── department/ {models.py}
│   ├── patient/    {models.py, schemas.py, service.py, router.py}
│   ├── appointment/{models.py, schemas.py, service.py, router.py}
│   ├── record/     {models.py, schemas.py, service.py, router.py}
│   ├── prescription/{models.py, schemas.py, service.py, router.py}
│   ├── billing/    {models.py, service.py, router.py}
│   ├── audit/      {models.py, service.py, router.py}
│   └── templates/  base.html, login.html, error.html, <module>/*.html
├── migrations/      env.py, versions/0001_initial.py
├── tests/           conftest.py, factories.py, test_<module>.py
└── Dockerfile
infra/docker-compose.yml
docs/security-requirements.md
```

---

### Task 1: Khung project, cấu hình, `/health`

**Files:**
- Create: `app/pyproject.toml`, `app/medicare/__init__.py`, `app/medicare/config.py`, `app/medicare/main.py`, `app/tests/test_health.py`, `app/.env.example`

**Interfaces:**
- Produces: `Settings` (pydantic-settings, đọc biến môi trường không có tiền tố): `env: Literal["development","test","production"] = "development"`, `database_url: str`, `secret_key: SecretStr` (bắt buộc, `min_length=32`), `session_max_age: int = 28800`. Hàm `create_app(settings: Settings | None = None) -> FastAPI`, với `settings=None` thì đọc `Settings()`. Gắn `app.state.settings`.

- [ ] **Step 1: Khởi tạo project**

`uv init --app --name medicare app`, sau đó `uv add fastapi "uvicorn[standard]" jinja2 python-multipart itsdangerous "sqlalchemy>=2" "psycopg[binary]" alembic argon2-cffi pydantic-settings faker` và `uv add --dev pytest httpx "testcontainers[postgres]" ruff`. Trong `pyproject.toml`: `requires-python = ">=3.12,<3.13"`, `[tool.pytest.ini_options] testpaths=["tests"]`, `[tool.ruff] line-length = 100`.

- [ ] **Step 2: Viết test thất bại** trong `app/tests/test_health.py`

```python
from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError
from medicare.config import Settings
from medicare.main import create_app

KEY = "x" * 32

def test_health_ok():
    app = create_app(Settings(env="test", database_url="postgresql+psycopg://u:p@h/db", secret_key=KEY))
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

def test_settings_require_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql+psycopg://u:p@h/db")

def test_secret_key_min_length():
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql+psycopg://u:p@h/db", secret_key="short")
```

- [ ] **Step 3: Chạy** `uv run pytest tests/test_health.py -v`. Kỳ vọng: FAIL (`ModuleNotFoundError: medicare.config`).
- [ ] **Step 4: Cài đặt** `Settings` và `create_app` có route `GET /health` → `{"status": "ok"}`. `.env.example` gồm `SECRET_KEY=change-me-change-me-change-me-32ch`, `DATABASE_URL=postgresql+psycopg://medicare:change-me@db:5432/medicare`, `ENV=development`, `DEMO_PASSWORD=change-me`.
- [ ] **Step 5: Chạy** `uv run pytest -v && uv run ruff check`. Kỳ vọng: 3 passed, ruff không báo lỗi.
- [ ] **Step 6: Commit** `feat(app): khung FastAPI, cấu hình và /health`

---

### Task 2: Cơ sở dữ liệu, toàn bộ model, migration, hạ tầng test

**Files:**
- Create: `app/medicare/db.py`, `app/medicare/<module>/models.py` (auth, department, patient, appointment, record, prescription, billing, audit), `app/alembic.ini`, `app/migrations/env.py`, `app/migrations/versions/0001_initial.py`, `app/tests/conftest.py`, `app/tests/factories.py`, `app/tests/test_models.py`

**Interfaces:**
- Produces:
  - `db.py`: `class Base(DeclarativeBase)`, `get_db() -> Iterator[Session]` (dependency FastAPI, dùng `sessionmaker` gắn với engine tạo từ `app.state.settings.database_url`; engine tạo một lần trong `create_app` và lưu ở `app.state.engine`).
  - `auth/models.py`: `class Role(StrEnum): ADMIN, RECEPTIONIST, DOCTOR, NURSE, PATIENT`. `User`: `id, username (unique), password_hash, full_name, role, department_id (FK, null), patient_id (FK patients, null, unique), is_active (default True), failed_login_count (default 0), locked_until (null), created_at`.
  - `department/models.py`: `Department: id, code (unique), name`.
  - `patient/models.py`: `Patient: id, code (unique, dạng "BN000001"), full_name, date_of_birth (Date), gender ("M"|"F"), national_id (unique, 12 chữ số), insurance_number (null, 15 ký tự), phone, address, department_id (FK, null), attending_doctor_id (FK users, null), created_at`.
  - `appointment/models.py`: `class AppointmentStatus(StrEnum): REQUESTED, CONFIRMED, CANCELLED, COMPLETED`. `Appointment: id, patient_id, doctor_id, scheduled_at (DateTime tz), reason, status, created_by_id, created_at`. Partial unique index `uq_doctor_slot_active` trên `(doctor_id, scheduled_at)` với `status <> 'CANCELLED'`.
  - `record/models.py`: `MedicalRecord: id, patient_id, doctor_id, visit_date (Date), symptoms, diagnosis_code, diagnosis_text, notes, created_at, updated_at`.
  - `prescription/models.py`: `Medicine: id, code (unique), name, unit, unit_price (Numeric(12,0)), is_active`. `Prescription: id, record_id, patient_id, doctor_id, note, created_at`. `PrescriptionItem: id, prescription_id, medicine_id, quantity (int > 0), dosage`.
  - `billing/models.py`: `class InvoiceStatus(StrEnum): UNPAID, PAID`. `Invoice: id, record_id (unique), patient_id, created_by_id, total_amount, coverage_rate (Numeric(3,2)), insurance_amount, patient_amount (đều Numeric(12,0)), status, created_at`.
  - `audit/models.py`: `AuditLog: id, actor_id, action (str), entity_type (str), entity_id (int), ip (str, null), at (DateTime tz, mặc định now)`.
  - `tests/factories.py`: `TEST_PASSWORD = "Passw0rd!"`. Các hàm `make_department(db, code="NOI") -> Department`, `make_user(db, role: Role, *, department=None, patient=None, username=None) -> User`, `make_patient(db, *, department=None, attending=None, insurance_number="DN4010123456789") -> Patient`, `make_record(db, patient, doctor) -> MedicalRecord`, `make_medicine(db, price=10000) -> Medicine`. Mỗi hàm `flush()` rồi trả về đối tượng, tự sinh giá trị unique nếu không truyền.
  - `tests/conftest.py`: fixture `db` (Session trong transaction, tự rollback sau mỗi test), `app` (`create_app` với `env="test"`, override `get_db` trả về `db`), `client` (`TestClient(app, raise_server_exceptions=False)`), và helper `csrf_token(client, path="/login") -> str`, `login(client, user) -> None`.

- [ ] **Step 1: Viết test thất bại** `app/tests/test_models.py`

```python
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone, timedelta
import pytest
from medicare.auth.models import Role
from medicare.appointment.models import Appointment, AppointmentStatus
from tests.factories import make_user, make_patient

def test_migration_creates_all_tables(db):
    names = set(db.execute(text("select tablename from pg_tables where schemaname='public'")).scalars())
    assert {"users","departments","patients","appointments","medical_records","medicines",
            "prescriptions","prescription_items","invoices","audit_logs"} <= names

def test_active_slot_unique_but_cancelled_allows_rebook(db):
    doc = make_user(db, Role.DOCTOR); p = make_patient(db)
    t = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)
    db.add(Appointment(patient_id=p.id, doctor_id=doc.id, scheduled_at=t, reason="x",
                       status=AppointmentStatus.CANCELLED, created_by_id=doc.id))
    db.add(Appointment(patient_id=p.id, doctor_id=doc.id, scheduled_at=t, reason="x",
                       status=AppointmentStatus.REQUESTED, created_by_id=doc.id))
    db.flush()  # cancelled không chặn
    db.add(Appointment(patient_id=p.id, doctor_id=doc.id, scheduled_at=t, reason="y",
                       status=AppointmentStatus.CONFIRMED, created_by_id=doc.id))
    with pytest.raises(IntegrityError):
        db.flush()
```

(import `text` từ `sqlalchemy`.)

- [ ] **Step 2: Chạy** `uv run pytest tests/test_models.py -v`. Kỳ vọng: FAIL (thiếu module).
- [ ] **Step 3: Cài đặt** `db.py`, các model, `alembic.ini` và `migrations/env.py` (đọc URL từ `config.get_main_option("sqlalchemy.url")`, nếu trống thì đọc biến môi trường `DATABASE_URL`; `target_metadata = Base.metadata`, import mọi module models). Tạo `0001_initial.py` bằng `alembic revision --autogenerate` rồi **tự thêm** partial index (`postgresql_where=text("status <> 'CANCELLED'")`) nếu autogenerate bỏ sót.
- [ ] **Step 4: Cài đặt** `conftest.py`. Đây là phần hạ tầng mà test không tự quyết định được:

```python
@pytest.fixture(scope="session")
def engine():
    with PostgresContainer("postgres:16-alpine", driver="psycopg") as pg:
        url = pg.get_connection_url()
        cfg = Config(str(APP_DIR / "alembic.ini"))
        cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
        command.upgrade(cfg, "head")
        eng = create_engine(url)
        yield eng
        eng.dispose()

@pytest.fixture
def db(engine):
    conn = engine.connect(); trans = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    yield session
    session.close(); trans.rollback(); conn.close()
```

`csrf_token` lấy giá trị từ thẻ `<meta name="csrf-token" content="...">` của trang `path` bằng regex. `login` gọi `POST /login` với `username`, `TEST_PASSWORD`, `csrf_token`, rồi `assert r.status_code == 303`. (Hai helper này dùng được từ Task 3.)

- [ ] **Step 5: Chạy** `uv run pytest -v`. Kỳ vọng: tất cả PASS (Docker phải đang chạy).
- [ ] **Step 6: Commit** `feat(app): data model, migration 0001 và hạ tầng test Postgres`

---

### Task 3: Xác thực, session, CSRF, khóa tài khoản, xử lý lỗi, giao diện nền

**Files:**
- Create: `app/medicare/common/{passwords,auth,csrf,errors,templating}.py`, `app/medicare/auth/router.py`, `app/medicare/templates/{base,login,error,home}.html`, `app/tests/test_auth.py`, `app/tests/test_errors.py`
- Modify: `app/medicare/main.py` (gắn `SessionMiddleware`, exception handler, router)

**Interfaces:**
- Produces:
  - `passwords.hash_password(plain: str) -> str`, `passwords.verify_password(hash: str, plain: str) -> bool` (argon2-cffi `PasswordHasher`).
  - `auth.get_current_user(request, db) -> User`: đọc `request.session["user_id"]`, **kiểm tra lại `is_active` mỗi request**, user không hợp lệ thì xóa session. Không có user → `HTTPException(401)` với đường dẫn `/api/*`, ngược lại `RedirectResponse("/login", 303)`, cài bằng exception riêng `LoginRequired` có handler.
  - `auth.require_roles(*roles: Role) -> Callable[..., User]`: sai vai trò → 403.
  - `auth.authenticate(db, username, password, now: datetime) -> User | None`: 5 lần sai liên tiếp → `locked_until = now + 15 phút`. Đang bị khóa thì trả `None` kể cả đúng mật khẩu. Đăng nhập đúng → reset bộ đếm.
  - `csrf.get_csrf_token(request) -> str` (sinh bằng `secrets.token_urlsafe(32)`, lưu trong session). `csrf.verify_csrf(request)` là dependency async đọc form field `csrf_token` hoặc header `X-CSRF-Token`, so sánh bằng `hmac.compare_digest`, sai thì 403. Gắn cho **mọi** route POST.
  - `errors.NotFound`, `errors.Conflict` (HTTPException 404/409 dùng `error.html`). Handler `Exception` → 500 với `error.html`, log `logger.exception` **không kèm tham số request**.
  - `templating.render(request, name, ctx, status_code=200)`: luôn đưa vào context `current_user` và `csrf_token`. `base.html` có `<meta name="csrf-token" content="{{ csrf_token }}">`.
  - Route: `GET /login`, `POST /login` (thành công → `session.clear()`, đặt `user_id` và CSRF mới, 303 về `/`; thất bại → 200 với thông báo chung "Tên đăng nhập hoặc mật khẩu không đúng"), `POST /logout` (xóa session, 303 về `/login`), `GET /` (trang chủ theo vai trò, cần đăng nhập), `GET/POST /account/password` (đổi mật khẩu, phải nhập đúng mật khẩu cũ, mật khẩu mới ≥ 10 ký tự).
  - `SessionMiddleware(secret_key, session_cookie="medicare_session", max_age=settings.session_max_age, same_site="lax", https_only=settings.env == "production")`.

- [ ] **Step 1: Viết test thất bại** `app/tests/test_auth.py`

```python
def test_login_success_redirects_home(client, db):
    u = make_user(db, Role.DOCTOR); login(client, u)
    assert client.get("/").status_code == 200

def test_login_wrong_password_generic_message(client, db):
    u = make_user(db, Role.DOCTOR)
    r = client.post("/login", data={"username": u.username, "password": "bad",
                                    "csrf_token": csrf_token(client)})
    assert r.status_code == 200 and "Tên đăng nhập hoặc mật khẩu không đúng" in r.text

def test_unknown_user_same_message(client):
    r = client.post("/login", data={"username": "nobody", "password": "x",
                                    "csrf_token": csrf_token(client)})
    assert "Tên đăng nhập hoặc mật khẩu không đúng" in r.text

def test_lockout_after_five_failures(client, db):
    u = make_user(db, Role.NURSE)
    for _ in range(5):
        client.post("/login", data={"username": u.username, "password": "bad",
                                    "csrf_token": csrf_token(client)})
    r = client.post("/login", data={"username": u.username, "password": TEST_PASSWORD,
                                    "csrf_token": csrf_token(client)}, follow_redirects=False)
    assert r.status_code == 200   # vẫn bị từ chối dù đúng mật khẩu

def test_post_without_csrf_is_403(client, db):
    u = make_user(db, Role.DOCTOR)
    r = client.post("/login", data={"username": u.username, "password": TEST_PASSWORD})
    assert r.status_code == 403

def test_anonymous_html_redirects_and_api_401(client):
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/v1/appointments").status_code == 401

def test_deactivated_user_session_is_rejected(client, db):
    u = make_user(db, Role.DOCTOR); login(client, u)
    u.is_active = False; db.flush()
    assert client.get("/", follow_redirects=False).status_code == 303

def test_session_cookie_flags(client, db):
    u = make_user(db, Role.DOCTOR)
    r = client.post("/login", data={"username": u.username, "password": TEST_PASSWORD,
                                    "csrf_token": csrf_token(client)}, follow_redirects=False)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie

def test_password_hash_is_argon2(db):
    assert make_user(db, Role.ADMIN).password_hash.startswith("$argon2id$")
```

(`/api/v1/appointments` được tạo ở Task 6. Đến lúc đó test này chỉ yêu cầu 401 cho đường dẫn `/api/` chưa xác thực. Cài `LoginRequired` sao cho mọi đường dẫn `/api/*` không có session đều trả 401 trước khi route được tìm tới, hoặc tạm đánh dấu test này `xfail` đến Task 6.)

- [ ] **Step 2: Viết test thất bại** `app/tests/test_errors.py`

```python
def test_unhandled_error_is_generic(app, client, caplog):
    @app.get("/_boom")
    def boom():
        raise RuntimeError("secret detail 012345678901")
    r = client.get("/_boom")
    assert r.status_code == 500
    assert "Đã có lỗi xảy ra" in r.text
    assert "Traceback" not in r.text and "secret detail" not in r.text

def test_404_page_generic(client):
    r = client.get("/khong-ton-tai")
    assert r.status_code == 404 and "Traceback" not in r.text
```

- [ ] **Step 3: Chạy** `uv run pytest tests/test_auth.py tests/test_errors.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 4: Cài đặt** các module trong `common/`, `auth/router.py` và các template nền. Giao diện dùng Bootstrap 5 qua CDN jsDelivr, có thuộc tính `integrity` (SRI) và `crossorigin="anonymous"`.
- [ ] **Step 5: Chạy** `uv run pytest -v`. Kỳ vọng: tất cả PASS.
- [ ] **Step 6: Commit** `feat(app): xác thực session, CSRF, khóa tài khoản, xử lý lỗi chung`

---

### Task 4: Tài liệu quy tắc bảo mật, policy, validators

**Files:**
- Create: `docs/security-requirements.md`, `app/medicare/policy.py`, `app/medicare/validators.py`, `app/tests/test_policy.py`, `app/tests/test_validators.py`

**Interfaces:**
- Produces:
  - `validators.is_valid_national_id(s: str) -> bool` (regex `^\d{12}$`). `validators.is_valid_insurance_number(s: str) -> bool` (regex `^[A-Z]{2}[1-5]\d{12}$`). `validators.coverage_rate(insurance_number: str | None) -> Decimal`: lấy ký tự thứ 3 theo mức hưởng BHYT: `1→1.00, 2→1.00, 3→0.95, 4→0.80, 5→1.00`; `None` hoặc sai định dạng → `0.00`. `validators.mask(value: str | None, visible: int = 4) -> str` (thay mọi ký tự trừ `visible` ký tự cuối bằng `*`; `None` → `""`).
  - `policy.py` (mọi hàm thuần, không truy vấn DB; `patient` là đối tượng `Patient` đã nạp):
    - `can_view_patient(user, patient) -> bool`: R-01, R-12
    - `can_edit_patient(user) -> bool`: chỉ RECEPTIONIST, ADMIN
    - `can_view_record(user, patient) -> bool`: R-01, R-02, R-12
    - `can_write_record(user, patient) -> bool`: R-02
    - `can_prescribe(user, patient) -> bool`: R-03
    - `can_view_invoice(user, patient) -> bool`: R-01, R-04
    - `can_view_identifiers(user, patient) -> bool`: R-11
    - `can_cancel_appointment(user, appt) -> bool`: R-13

- [ ] **Step 1: Viết `docs/security-requirements.md`**: phần giới thiệu, ma trận phân quyền (vai trò × tài nguyên × hành động), và các quy tắc với tiêu đề `### R-xx: <tên>` (đúng Hợp đồng 1), nguyên văn như sau:
  - R-01 Bệnh nhân chỉ xem được hồ sơ, bệnh án, đơn thuốc, hóa đơn, lịch hẹn của chính mình.
  - R-02 Bác sĩ xem được bệnh án của bệnh nhân thuộc khoa mình hoặc do mình phụ trách. Chỉ bác sĩ phụ trách (`attending_doctor_id`) được tạo hoặc sửa bệnh án.
  - R-03 Chỉ bác sĩ phụ trách được kê đơn. Y tá chỉ xem đơn của bệnh nhân thuộc khoa mình.
  - R-04 Tỷ lệ BHYT chi trả và số tiền được tính ở server từ mã thẻ BHYT. Client không gửi lên tỷ lệ hay số tiền.
  - R-05 Mọi lần xem, tạo, sửa bệnh án (cả HTML lẫn API) đều ghi audit log: người thực hiện, hành động, đối tượng, IP, thời điểm.
  - R-06 Audit log chỉ được thêm, không có chức năng sửa hay xóa. Chỉ ADMIN xem được.
  - R-07 Mật khẩu băm bằng Argon2id. Khóa tài khoản 15 phút sau 5 lần sai liên tiếp. Thông báo lỗi đăng nhập không tiết lộ tài khoản có tồn tại hay không.
  - R-08 Cookie session có HttpOnly, SameSite=Lax, Secure ở môi trường production. Mọi request thay đổi dữ liệu phải có CSRF token. Đăng nhập thì tạo session mới.
  - R-09 Secret chỉ đọc từ biến môi trường. Ứng dụng không khởi động nếu thiếu `SECRET_KEY` hợp lệ.
  - R-10 Không trả stack trace cho client. Không ghi PII (CCCD, mã BHYT, chẩn đoán, ghi chú, mật khẩu) vào log.
  - R-11 CCCD và mã BHYT được che, chỉ hiện 4 ký tự cuối, trừ với RECEPTIONIST, ADMIN và chính bệnh nhân đó.
  - R-12 Lễ tân và Admin không xem nội dung bệnh án (chẩn đoán, ghi chú, đơn thuốc).
  - R-13 Không đặt lịch hẹn trong quá khứ. Một bác sĩ không có hai lịch hẹn còn hiệu lực trùng giờ. Bệnh nhân chỉ được hủy lịch của chính mình khi lịch đang ở trạng thái REQUESTED.
  - R-14 Server không dùng đường dẫn file hay URL do người dùng cung cấp mà chưa đối chiếu với danh sách cho phép (allowlist).
  - R-15 Đối tượng không tồn tại và đối tượng không có quyền truy cập đều trả về 404 giống hệt nhau.
- [ ] **Step 2: Viết test thất bại** `test_validators.py`:

```python
@pytest.mark.parametrize("code,rate", [("DN1010123456789","1.00"),("DN3010123456789","0.95"),
    ("HT4010123456789","0.80"),("CB5010123456789","1.00"),("XX9010123456789","0.00"),
    (None,"0.00"),("dn4010123456789","0.00"),("DN40101234","0.00")])
def test_coverage_rate(code, rate):
    assert coverage_rate(code) == Decimal(rate)

def test_mask():
    assert mask("012345678901") == "********8901"
    assert mask(None) == ""

def test_national_id():
    assert is_valid_national_id("012345678901") and not is_valid_national_id("12345")
```

`test_policy.py` là bảng tham số hóa (`@pytest.mark.parametrize`) trên các đối tượng dựng sẵn **không cần DB** (khởi tạo `User(...)` và `Patient(...)` trong bộ nhớ). Gồm tối thiểu các trường hợp:

```python
# (role, quan hệ, hàm, kỳ vọng)
("PATIENT","self","can_view_record",True), ("PATIENT","other","can_view_record",False),
("DOCTOR","attending","can_write_record",True), ("DOCTOR","same_dept","can_write_record",False),
("DOCTOR","same_dept","can_view_record",True), ("DOCTOR","other_dept","can_view_record",False),
("NURSE","same_dept","can_view_record",True), ("NURSE","same_dept","can_prescribe",False),
("RECEPTIONIST","any","can_view_record",False), ("ADMIN","any","can_view_record",False),
("RECEPTIONIST","any","can_view_identifiers",True), ("DOCTOR","attending","can_view_identifiers",False),
("PATIENT","self","can_view_invoice",True), ("NURSE","same_dept","can_view_invoice",False),
```

- [ ] **Step 3: Chạy** `uv run pytest tests/test_policy.py tests/test_validators.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 4: Cài đặt** `validators.py` và `policy.py`. Docstring mỗi hàm `can_*` ghi mã R-xx.
- [ ] **Step 5: Chạy** `uv run pytest -v`. Kỳ vọng: PASS.
- [ ] **Step 6: Commit** `feat(app): quy tắc bảo mật R-01..R-15, policy và validators`

---

### Task 5: Module bệnh nhân

**Files:**
- Create: `app/medicare/patient/{schemas,service,router}.py`, `app/medicare/templates/patient/{list,detail,form,me}.html`, `app/tests/test_patient.py`

**Interfaces:**
- Consumes: `policy.can_view_patient`, `can_edit_patient`, `can_view_identifiers`; `validators.*`; `require_roles`, `verify_csrf`, `NotFound`.
- Produces: `service.get_patient_for(db, user, patient_id) -> Patient` (không tồn tại **hoặc** không có quyền → `NotFound`). Hàm này được dùng lại ở các Task 6–9. `service.search_patients(db, user, q: str | None) -> list[Patient]` (lọc theo phạm vi của vai trò; tìm `code` hoặc `full_name` bằng `ilike` có bind parameter; tối đa 50 kết quả).
- Route:
  - `GET /patients?q=` (RECEPTIONIST, ADMIN, DOCTOR, NURSE)
  - `GET /patients/new`, `POST /patients` (RECEPTIONIST)
  - `GET /patients/{id}`
  - `GET /patients/{id}/edit`, `POST /patients/{id}/edit` (RECEPTIONIST)
  - `GET /me` (PATIENT)
  - `GET /api/v1/patients/{id}` → JSON `{id, code, full_name, date_of_birth, national_id, insurance_number, department_id}`, trong đó hai trường định danh được che theo R-11.
  - Mã bệnh nhân sinh tự động `BN` + số 6 chữ số.

- [ ] **Step 1: Viết test thất bại** `test_patient.py`:

```python
def test_receptionist_creates_patient(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post("/patients", data={"full_name":"Nguyễn Văn A","date_of_birth":"1990-01-01",
        "gender":"M","national_id":"012345678901","insurance_number":"DN4010123456789",
        "phone":"0901234567","address":"Hà Nội","csrf_token":csrf_token(client,"/patients/new")},
        follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/patients/")

def test_invalid_national_id_rerenders_400(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post("/patients", data={"full_name":"A","date_of_birth":"1990-01-01","gender":"M",
        "national_id":"123","phone":"0901","address":"x","csrf_token":csrf_token(client,"/patients/new")})
    assert r.status_code == 400 and "CCCD" in r.text

def test_doctor_cannot_create_patient(client, db):
    login(client, make_user(db, Role.DOCTOR))
    assert client.post("/patients", data={"csrf_token": csrf_token(client, "/")}).status_code == 403

def test_patient_sees_only_self_via_api(client, db):
    me = make_patient(db); other = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=me))
    assert client.get(f"/api/v1/patients/{me.id}").status_code == 200
    assert client.get(f"/api/v1/patients/{other.id}").status_code == 404

def test_patient_detail_forbidden_and_missing_are_identical(client, db):
    other = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    a = client.get(f"/api/v1/patients/{other.id}"); b = client.get("/api/v1/patients/999999")
    assert a.status_code == b.status_code == 404 and a.json() == b.json()

def test_identifiers_masked_for_doctor(client, db):
    dept = make_department(db); doc = make_user(db, Role.DOCTOR, department=dept)
    p = make_patient(db, department=dept, attending=doc)
    login(client, doc)
    body = client.get(f"/api/v1/patients/{p.id}").json()
    assert body["national_id"].startswith("********") and len(body["national_id"]) == 12

def test_nurse_other_department_cannot_see(client, db):
    p = make_patient(db, department=make_department(db, "NGOAI"))
    login(client, make_user(db, Role.NURSE, department=make_department(db, "NHI")))
    assert client.get(f"/patients/{p.id}").status_code == 404

def test_search_with_sql_metacharacters_is_safe(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get("/patients", params={"q": "' OR 1=1 --"}).status_code == 200
```

- [ ] **Step 2: Chạy** `uv run pytest tests/test_patient.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** schemas (Pydantic, kiểm tra định dạng bằng `validators`), service, router và template. Lỗi validate → hiển thị lại form với 400 và thông báo tiếng Việt chứa tên trường ("CCCD", "Mã BHYT").
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS.
- [ ] **Step 5: Commit** `feat(app): module bệnh nhân với phân quyền theo đối tượng và che định danh`

---

### Task 6: Module lịch hẹn

**Files:**
- Create: `app/medicare/appointment/{schemas,service,router}.py`, `app/medicare/templates/appointment/{list,form}.html`, `app/tests/test_appointment.py`

**Interfaces:**
- Consumes: `patient.service.get_patient_for`, `policy.can_cancel_appointment`, `errors.Conflict`.
- Produces: `service.book(db, user, patient_id, doctor_id, scheduled_at, reason, now) -> Appointment`: `scheduled_at <= now` thì `ValueError("past")`. Bắt `IntegrityError` của `uq_doctor_slot_active` rồi đổi thành `Conflict`. PATIENT chỉ đặt cho chính mình, RECEPTIONIST đặt cho bất kỳ ai.
- Route:
  - `GET /appointments`: lọc theo vai trò. PATIENT thấy lịch của mình, DOCTOR thấy lịch của mình, RECEPTIONIST/ADMIN thấy tất cả.
  - `GET /appointments/new`, `POST /appointments` (PATIENT, RECEPTIONIST)
  - `POST /appointments/{id}/confirm` (RECEPTIONIST)
  - `POST /appointments/{id}/cancel` (theo R-13)
  - `GET /api/v1/appointments`: danh sách JSON của chính người gọi.
  - Giờ hẹn phải là mốc 30 phút (phút = 0 hoặc 30), sai thì 400.

- [ ] **Step 1: Viết test thất bại**:

```python
def test_patient_books_own_appointment(client, db): ...   # 303, status REQUESTED
def test_patient_cannot_book_for_other_patient(client, db): ...   # 404
def test_booking_in_past_rejected_400(client, db): ...
def test_double_booking_rejected_at_db_level(client, db):
    # hai lịch cùng doctor_id, cùng scheduled_at qua 2 request → request thứ hai trả 409
def test_patient_cancels_only_requested_own(client, db): ...  # CONFIRMED → 403; của người khác → 404
def test_api_lists_only_own(client, db): ...  # JSON không chứa id lịch của bệnh nhân khác
```

Mỗi test ghi rõ dữ liệu (dùng factories, `scheduled_at` = ngày mai lúc 09:00 UTC) và assert mã trạng thái như comment ở trên.

- [ ] **Step 2: Chạy** `uv run pytest tests/test_appointment.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** service, router, template.
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS. Bỏ `xfail` ở `test_anonymous_html_redirects_and_api_401` nếu đã đặt ở Task 3.
- [ ] **Step 5: Commit** `feat(app): module lịch hẹn, chống đặt trùng ở tầng DB`

---

### Task 7: Module bệnh án + audit log

**Files:**
- Create: `app/medicare/record/{schemas,service,router}.py`, `app/medicare/audit/service.py`, `app/medicare/templates/record/{list,detail,form}.html`, `app/tests/test_record.py`

**Interfaces:**
- Consumes: `get_patient_for`, `policy.can_view_record`, `can_write_record`.
- Produces:
  - `audit.service.log_access(db, actor: User, action: str, entity_type: str, entity_id: int, ip: str | None) -> None`. Các `action` dùng trong code: `VIEW_RECORD, CREATE_RECORD, UPDATE_RECORD, VIEW_PRESCRIPTION, CREATE_PRESCRIPTION`.
  - `record.service.get_record_for(db, user, record_id, ip) -> MedicalRecord`: không có quyền → `NotFound`, có quyền thì ghi `VIEW_RECORD`. Hàm này được Task 8 và 9 dùng lại.
- Route:
  - `GET /patients/{pid}/records`
  - `GET /records/{id}`
  - `GET /patients/{pid}/records/new`, `POST /patients/{pid}/records` (bác sĩ phụ trách)
  - `GET /records/{id}/edit`, `POST /records/{id}/edit`
  - `GET /api/v1/records/{id}`
  - `notes` hiển thị dạng văn bản đã escape, giữ xuống dòng bằng CSS `white-space: pre-wrap` (không dùng `|safe`).

- [ ] **Step 1: Viết test thất bại**:

```python
def test_attending_doctor_creates_record_and_audit_logged(client, db): ...
    # POST → 303; AuditLog(action="CREATE_RECORD", entity_id=record.id, actor_id=doc.id) tồn tại
def test_view_record_writes_audit_for_html_and_api(client, db): ...
    # GET /records/{id} và GET /api/v1/records/{id} → 2 dòng VIEW_RECORD
def test_same_department_doctor_can_view_not_edit(client, db): ...  # GET 200; POST edit → 404
def test_receptionist_cannot_view_record(client, db): ...  # 404, và không có dòng audit nào
def test_patient_cannot_view_other_patient_record_via_api(client, db): ...  # 404
def test_notes_are_escaped(client, db):
    # notes="<script>alert(1)</script>" → response chứa "&lt;script&gt;", không chứa "<script>alert"
def test_record_creation_does_not_log_pii(client, db, caplog):
    # caplog.set_level(DEBUG); tạo bệnh án với diagnosis_text="Ung thư phổi"
    # → "Ung thư phổi" not in caplog.text và patient.national_id not in caplog.text
```

- [ ] **Step 2: Chạy** `uv run pytest tests/test_record.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** `audit/service.py`, `record/*`, template. IP lấy từ `request.client.host`.
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS.
- [ ] **Step 5: Commit** `feat(app): module bệnh án với audit log (R-02, R-05, R-12)`

---

### Task 8: Danh mục thuốc và đơn thuốc

**Files:**
- Create: `app/medicare/prescription/{schemas,service,router}.py`, `app/medicare/templates/prescription/{form,detail,medicines}.html`, `app/tests/test_prescription.py`

**Interfaces:**
- Consumes: `get_record_for`, `policy.can_prescribe`, `audit.service.log_access`.
- Produces: `service.create_prescription(db, user, record_id, items: list[tuple[int, int, str]], note, ip) -> Prescription` (mỗi phần tử là `medicine_id, quantity, dosage`; `quantity` phải ≥ 1; thuốc không còn hoạt động thì 400). `service.prescription_total(p: Prescription) -> Decimal`, được Task 9 dùng.
- Route:
  - `GET /records/{id}/prescriptions/new`, `POST /records/{id}/prescriptions` (bác sĩ phụ trách). Form gồm các dòng `medicine_id[]`, `quantity[]`, `dosage[]`.
  - `GET /prescriptions/{id}`: người xem được bệnh án tương ứng.
  - `GET /admin/medicines`, `POST /admin/medicines` (ADMIN).

- [ ] **Step 1: Viết test thất bại**:

```python
def test_attending_doctor_prescribes(client, db): ...  # 303; CREATE_PRESCRIPTION được ghi audit
def test_nurse_cannot_prescribe(client, db): ...  # 403 (sai vai trò ở route)
def test_non_attending_doctor_cannot_prescribe(client, db): ...  # 404
def test_quantity_must_be_positive(client, db): ...  # quantity=0 → 400
def test_prescription_total(db):
    # 2 thuốc: 10_000 × 3 + 25_000 × 2 → Decimal("80000")
def test_admin_adds_medicine_and_doctor_cannot(client, db): ...  # ADMIN 303; DOCTOR 403
```

- [ ] **Step 2: Chạy** `uv run pytest tests/test_prescription.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** service, router, template.
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS.
- [ ] **Step 5: Commit** `feat(app): danh mục thuốc và kê đơn (R-03)`

---

### Task 9: Viện phí và BHYT

**Files:**
- Create: `app/medicare/billing/{service,router}.py`, `app/medicare/templates/billing/{list,detail}.html`, `app/tests/test_billing.py`

**Interfaces:**
- Consumes: `validators.coverage_rate`, `prescription.service.prescription_total`, `policy.can_view_invoice`.
- Produces: hằng `EXAM_FEE = Decimal("150000")`. `service.create_invoice(db, user, record_id) -> Invoice`, với cách tính:
  - `total = EXAM_FEE + tổng các đơn thuốc của bệnh án`
  - `insurance_amount = (total × coverage_rate).quantize(Decimal("1"), ROUND_HALF_UP)`
  - `patient_amount = total − insurance_amount`
  - Mỗi bệnh án chỉ có một hóa đơn; tạo lần hai thì `Conflict`.
- Route:
  - `POST /records/{id}/invoice` (RECEPTIONIST; **form chỉ có `csrf_token`**, mọi giá trị tiền do server tính theo R-04)
  - `GET /invoices` (RECEPTIONIST, ADMIN thấy tất cả; PATIENT thấy của mình)
  - `GET /invoices/{id}`
  - `POST /invoices/{id}/pay` (RECEPTIONIST)
  - Lễ tân tạo hóa đơn **không** cần quyền xem bệnh án: service truy vấn record theo id, không qua `get_record_for`, và không ghi audit `VIEW_RECORD`.

- [ ] **Step 1: Viết test thất bại**:

```python
def test_invoice_with_80_percent_coverage(client, db):
    # BHYT "HT4010123456789", đơn thuốc 80_000 → total 230_000, insurance 184_000, patient 46_000
def test_invoice_without_insurance(client, db):  # insurance_number=None → insurance 0
def test_client_supplied_amounts_are_ignored(client, db):
    # POST kèm coverage_rate=1.0, total_amount=1 → hóa đơn vẫn tính đúng như test đầu
def test_duplicate_invoice_conflict(client, db): ...  # lần 2 → 409
def test_patient_sees_only_own_invoice(client, db): ...  # của người khác → 404
def test_receptionist_invoice_does_not_expose_diagnosis(client, db):
    # trang /invoices/{id} không chứa diagnosis_text của bệnh án
```

- [ ] **Step 2: Chạy** `uv run pytest tests/test_billing.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** service, router, template.
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS.
- [ ] **Step 5: Commit** `feat(app): viện phí và tính BHYT ở server (R-04)`

---

### Task 10: Quản trị: tài khoản và xem audit log

**Files:**
- Create: `app/medicare/auth/admin_router.py`, `app/medicare/audit/router.py`, `app/medicare/templates/admin/{users,audit}.html`, `app/tests/test_admin.py`

**Interfaces:**
- Route:
  - `GET /admin/users`, `POST /admin/users`: tạo tài khoản với `username, full_name, role, department_id?, patient_id?, password`. Mật khẩu ≥ 10 ký tự. PATIENT bắt buộc có `patient_id`; DOCTOR và NURSE bắt buộc có `department_id`.
  - `POST /admin/users/{id}/deactivate`
  - `GET /admin/audit?record_id=&page=` (50 dòng mỗi trang, mới nhất trước)
  - Tất cả chỉ dành cho ADMIN. Không có route nào sửa hoặc xóa `AuditLog` (R-06).

- [ ] **Step 1: Viết test thất bại**:

```python
def test_admin_creates_doctor_requires_department(client, db): ...  # thiếu department → 400
def test_non_admin_cannot_access_admin(client, db): ...  # DOCTOR GET /admin/users → 403
def test_deactivate_user_kills_their_access(client, db): ...  # sau khi vô hiệu hóa, đăng nhập thất bại
def test_audit_page_filters_by_record(client, db): ...  # chỉ hiện các dòng có entity_id = record_id
def test_no_mutating_audit_routes(app):
    paths = [r.path for r in app.routes if getattr(r, "methods", None) and
             ({"PUT","PATCH","DELETE"} & r.methods or "POST" in r.methods)]
    assert not any("audit" in p for p in paths)
```

- [ ] **Step 2: Chạy** `uv run pytest tests/test_admin.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** router và template.
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS.
- [ ] **Step 5: Commit** `feat(app): quản trị tài khoản và xem audit log (R-06)`

---

### Task 11: Dữ liệu mẫu, Docker, docker compose

**Files:**
- Create: `app/medicare/seed.py`, `app/Dockerfile`, `app/.dockerignore`, `app/docker-entrypoint.sh`, `infra/docker-compose.yml`, `app/tests/test_seed.py`, `app/README.md`

**Interfaces:**
- Produces:
  - `seed.run(db, *, password: str, rng_seed: int = 42) -> dict[str, int]`: tạo 3 khoa (`NOI` Nội, `NGOAI` Ngoại, `NHI` Nhi); tài khoản `admin`, `letan1`, `bacsi1..4`, `yta1..3`, `benhnhan1..5` (5 bệnh nhân đầu được gắn tài khoản); 50 bệnh nhân, 100 bệnh án, 20 loại thuốc, 30 lịch hẹn. Dữ liệu sinh bằng Faker `vi_VN` với `seed(rng_seed)`. Trả về số lượng từng loại.
  - `seed.main() -> int` (điểm vào của `python -m medicare.seed`, `if __name__ == "__main__": sys.exit(main())`): chỉ chạy khi `ENV == "development"`, đọc mật khẩu từ `DEMO_PASSWORD` (thiếu thì thoát với mã 1). Môi trường khác thì từ chối chạy (mã 1).
  - Image: base `python:3.12-slim`, `uv` copy từ `ghcr.io/astral-sh/uv`, cài bằng `uv sync --frozen --no-dev`, **chạy bằng user không phải root** (`USER app`), có `HEALTHCHECK` gọi `/health`. Entrypoint chạy `alembic upgrade head` rồi `uvicorn medicare.main:create_app --factory --host 0.0.0.0 --port 8000`.
  - Compose: service `db` (`postgres:16-alpine`, healthcheck `pg_isready`, volume có tên) và `app` (build `../app`, `env_file: ../app/.env`, `depends_on: db: condition: service_healthy`, cổng `8000:8000`).

- [ ] **Step 1: Viết test thất bại** `test_seed.py`:

```python
def test_seed_counts_and_idempotent_users(db):
    counts = run(db, password="Demo-password-1")
    assert counts["patients"] == 50 and counts["records"] == 100 and counts["users"] == 14
    assert db.scalar(select(User).where(User.username == "bacsi1")).role == Role.DOCTOR

def test_seed_refuses_outside_development(monkeypatch):
    monkeypatch.setenv("ENV", "production"); monkeypatch.setenv("DEMO_PASSWORD", "x"*12)
    assert main() == 1
```

- [ ] **Step 2: Chạy** `uv run pytest tests/test_seed.py -v`. Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt** `seed.py`, Dockerfile, entrypoint, compose, `README.md` (hướng dẫn: copy `.env.example` thành `.env`, `docker compose -f infra/docker-compose.yml up -d --build`, seed bằng `docker compose ... exec app python -m medicare.seed`, đăng nhập bằng `bacsi1`).
- [ ] **Step 4: Chạy** `uv run pytest -v`. Kỳ vọng: PASS toàn bộ.
- [ ] **Step 5: Kiểm tra end-to-end:** `docker compose -f infra/docker-compose.yml up -d --build`, sau đó `curl -fsS localhost:8000/health`. Kỳ vọng: `{"status":"ok"}`. Seed xong, đăng nhập `bacsi1` trên trình duyệt và xem được danh sách bệnh nhân khoa mình. Chạy `docker compose ... exec app whoami`, kỳ vọng `app`.
- [ ] **Step 6: Commit** `feat(app): dữ liệu mẫu, Dockerfile chạy non-root, docker compose`
