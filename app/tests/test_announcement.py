from sqlalchemy import select

from medicare.announcement.models import Announcement
from medicare.auth.models import Role
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_user

BODY = ("<p>Khoa Dược ngừng cấp phát từ <strong>17h</strong> thứ Sáu để kiểm kê.</p>"
        "<ul><li>Đơn cấp cứu: liên hệ trực dược</li><li>Đơn ngoại trú: nhận sáng thứ Hai</li></ul>"
        '<p>Chi tiết: <a href="https://medicare.example/kiem-ke">quy trình kiểm kê</a></p>')


def post(client, title="Lịch kiểm kê kho thuốc", body=BODY):
    data = {"title": title, "body": body,
            "csrf_token": csrf_token(client, "/admin/announcements")}
    return client.post("/admin/announcements", data=data, follow_redirects=False)


def test_admin_posts_announcement_shown_on_home(client, db):
    admin = make_user(db, Role.ADMIN)
    login(client, admin)
    r = post(client)
    assert r.status_code == 303 and r.headers["location"] == "/admin/announcements"
    a = db.scalar(select(Announcement))
    assert a.author_id == admin.id and a.body_html == BODY
    client.cookies.clear()
    login(client, make_user(db, Role.NURSE, department=make_department(db)))
    html = client.get("/").text
    assert "Lịch kiểm kê kho thuốc" in html and "<strong>17h</strong>" in html
    assert '<a href="https://medicare.example/kiem-ke">quy trình kiểm kê</a>' in html


def test_patients_see_announcements_too(client, db):
    login(client, make_user(db, Role.ADMIN))
    post(client, title="Nghỉ lễ Quốc khánh", body="<p>Phòng khám ngoại trú nghỉ ngày 2/9.</p>")
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    assert "Nghỉ lễ Quốc khánh" in client.get("/").text


def test_plain_text_body_is_kept(client, db):
    login(client, make_user(db, Role.ADMIN))
    post(client, body="Họp giao ban lúc 7h30 tại hội trường A")
    assert db.scalar(select(Announcement.body_html)) == "Họp giao ban lúc 7h30 tại hội trường A"


def test_title_and_body_required(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = post(client, title="  ")
    assert r.status_code == 400 and "Tiêu đề" in r.text
    r = post(client, body="")
    assert r.status_code == 400 and "Nội dung" in r.text
    assert db.scalar(select(Announcement)) is None


def test_body_length_limited(client, db):
    login(client, make_user(db, Role.ADMIN))
    assert post(client, body="a" * 5001).status_code == 400


def test_only_admin_manages_announcements(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get("/admin/announcements").status_code == 403
    r = client.post("/admin/announcements",
                    data={"title": "x", "body": "y", "csrf_token": csrf_token(client, "/")})
    assert r.status_code == 403
    assert db.scalar(select(Announcement)) is None


def test_post_without_csrf_is_403(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = client.post("/admin/announcements", data={"title": "x", "body": "y"})
    assert r.status_code == 403


def test_admin_removes_announcement(client, db):
    login(client, make_user(db, Role.ADMIN))
    post(client)
    a = db.scalar(select(Announcement))
    r = client.post(f"/admin/announcements/{a.id}/delete",
                    data={"csrf_token": csrf_token(client, "/admin/announcements")},
                    follow_redirects=False)
    assert r.status_code == 303
    assert db.scalar(select(Announcement)) is None
    r = client.post(f"/admin/announcements/{a.id}/delete",
                    data={"csrf_token": csrf_token(client, "/admin/announcements")})
    assert r.status_code == 404
