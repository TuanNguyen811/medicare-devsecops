"""Generate traffic against the local MediCare deployment to exercise monitoring (spec 7.3).

    python deploy/simulate-traffic.py --mode normal      [--duration 300]
    python deploy/simulate-traffic.py --mode brute-force [--user bacsi4] [--attempts 30]
    python deploy/simulate-traffic.py --mode idor-probe  [--user benhnhan1] [--max-id 40]
    python deploy/simulate-traffic.py --mode bulk-read   [--user bacsi1] [--records 40]

Target: --base (default http://127.0.0.1:18000, the port-forward of deploy/README.md). Only
127.0.0.1 or localhost is accepted: this script must never be pointed at someone else's system.
The demo password comes from DEMO_PASSWORD, or else from the cluster Secret medicare-env.

Modes and the alerts they should raise (deploy/monitoring/config/rules.yml):
  normal       every role logs in and browses at a human pace, books an appointment: no alert;
  brute-force  wrong passwords for one account: BruteForceSuspected and AccountLockout
               (the account stays locked for 15 minutes);
  idor-probe   a patient walks through record ids it does not own: AuthzDeniedSpike;
  bulk-read    a doctor opens every record it may see, fast: RecordAccessSpike.
Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import os
import random
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
TIMEOUT_S = 20
_CSRF = re.compile(r'name="csrf-token"\s+content="([^"]+)"')
_PATIENT_LINK = re.compile(r'href="/patients/(\d+)"')
_RECORD_LINK = re.compile(r'href="/records/(\d+)"')
_OPTION = re.compile(r'<option value="(\d+)"')  # a patient's booking form lists doctors only
ROLE_USERS = ["letan1", "bacsi1", "yta1", "benhnhan1", "admin"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    """One browser: its own cookie jar, no redirect following, status codes tallied."""

    def __init__(self, base: str, stats: Counter) -> None:
        self.base = base.rstrip("/")
        self.stats = stats
        self.csrf = ""
        self._opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, path: str, data: dict | None = None) -> tuple[int, str]:
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data | {"csrf_token": self.csrf}).encode()
        req = urllib.request.Request(self.base + path, data=body,
                                     method="POST" if body is not None else "GET")
        try:
            resp = self._opener.open(req, timeout=TIMEOUT_S)
        except urllib.error.HTTPError as exc:  # 3xx (not followed) and error statuses
            resp = exc
        html = resp.read().decode("utf-8", errors="replace")
        token = _CSRF.search(html)
        if token:
            self.csrf = token.group(1)
        self.stats[resp.status] += 1
        return resp.status, html

    def login(self, username: str, password: str) -> bool:
        self.request("/login")
        status, _ = self.request("/login", {"username": username, "password": password})
        if status == 303:
            self.request("/")  # fresh CSRF token for the new session
        return status == 303


def demo_password() -> str:
    password = os.environ.get("DEMO_PASSWORD", "")
    if password:
        return password
    try:
        out = subprocess.run(
            ["kubectl", "-n", "medicare", "get", "secret", "medicare-env",
             "-o", "jsonpath={.data.DEMO_PASSWORD}"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        sys.exit(f"simulate-traffic: set DEMO_PASSWORD (kubectl fallback failed: {exc})")
    return base64.b64decode(out).decode()


def pause(lo: float, hi: float) -> None:
    time.sleep(random.uniform(lo, hi))


def browse_once(c: Client, username: str) -> None:
    """A few pages a person in this role would open."""
    if username.startswith(("bacsi", "yta")):
        _, html = c.request("/patients")
        patients = _PATIENT_LINK.findall(html)
        if patients:
            pid = random.choice(patients)
            pause(2, 5)
            c.request(f"/patients/{pid}")
            pause(2, 5)
            _, html = c.request(f"/patients/{pid}/records")
            records = _RECORD_LINK.findall(html)
            if records:
                pause(2, 5)
                c.request(f"/records/{random.choice(records)}")
    elif username.startswith("benhnhan"):
        for path in ("/me", "/appointments", "/invoices"):
            c.request(path)
            pause(2, 5)
    elif username.startswith("letan"):
        for path in ("/patients", "/appointments", "/invoices"):
            c.request(path)
            pause(2, 5)
    else:
        for path in ("/admin/users", "/admin/audit"):
            c.request(path)
            pause(2, 5)


def book_appointment(c: Client) -> None:
    """A patient books a slot on the 30-minute grid; a taken slot (409) is normal."""
    _, html = c.request("/appointments/new")
    doctors = _OPTION.findall(html)
    if not doctors:
        return
    day = datetime.now() + timedelta(days=random.randint(2, 30))
    slot = day.replace(hour=random.randint(8, 15), minute=random.choice((0, 30)),
                       second=0, microsecond=0)
    c.request("/appointments", {"doctor_id": random.choice(doctors),
                                "scheduled_at": slot.strftime("%Y-%m-%dT%H:%M"),
                                "reason": "Khám định kỳ"})


def mode_normal(base: str, password: str, duration: int, stats: Counter) -> None:
    clients = {u: Client(base, stats) for u in ROLE_USERS}
    for user, c in clients.items():
        if not c.login(user, password):
            sys.exit(f"simulate-traffic: login failed for {user}")
    book_appointment(clients["benhnhan1"])
    end = time.monotonic() + duration
    while time.monotonic() < end:
        user = random.choice(ROLE_USERS)
        browse_once(clients[user], user)
        pause(3, 8)


def mode_brute_force(base: str, user: str, attempts: int, stats: Counter) -> None:
    c = Client(base, stats)
    for _ in range(attempts):
        c.login(user, secrets.token_urlsafe(12))  # never the real password
        time.sleep(0.3)
    print(f"{user} is now locked for 15 minutes (R-07).")


def mode_idor_probe(base: str, password: str, user: str, max_id: int, stats: Counter) -> None:
    c = Client(base, stats)
    if not c.login(user, password):
        sys.exit(f"simulate-traffic: login failed for {user}")
    seen = Counter()
    for rid in range(1, max_id + 1):
        status, _ = c.request(f"/api/v1/records/{rid}")
        seen[status] += 1
        time.sleep(0.2)
    print(f"{user} probed records 1..{max_id}: {seen[200]} readable (own), "
          f"{seen[404]} refused or missing (same 404, R-15).")


def mode_bulk_read(base: str, password: str, user: str, limit: int, stats: Counter) -> None:
    c = Client(base, stats)
    if not c.login(user, password):
        sys.exit(f"simulate-traffic: login failed for {user}")
    _, html = c.request("/patients")
    opened = 0
    for pid in dict.fromkeys(_PATIENT_LINK.findall(html)):
        _, page = c.request(f"/patients/{pid}/records")
        for rid in dict.fromkeys(_RECORD_LINK.findall(page)):
            c.request(f"/records/{rid}")
            opened += 1
            time.sleep(0.2)
            if opened >= limit:
                print(f"{user} opened {opened} records.")
                return
    print(f"{user} opened {opened} records (all it may see).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", required=True,
                    choices=["normal", "brute-force", "idor-probe", "bulk-read"])
    ap.add_argument("--base", default="http://127.0.0.1:18000")
    ap.add_argument("--duration", type=int, default=300, help="normal: seconds to run")
    ap.add_argument("--user", help="account to attack or to act as")
    ap.add_argument("--attempts", type=int, default=30, help="brute-force: wrong passwords")
    ap.add_argument("--max-id", type=int, default=40, help="idor-probe: highest record id")
    ap.add_argument("--records", type=int, default=40, help="bulk-read: records to open")
    args = ap.parse_args(argv)

    url = urllib.parse.urlparse(args.base)
    if url.scheme != "http" or url.hostname not in ALLOWED_HOSTS:
        print("simulate-traffic: --base must be http://127.0.0.1:<port> or http://localhost:<port>",
              file=sys.stderr)
        return 2

    stats: Counter = Counter()
    started = time.monotonic()
    try:
        if args.mode == "normal":
            mode_normal(args.base, demo_password(), args.duration, stats)
        elif args.mode == "brute-force":
            mode_brute_force(args.base, args.user or "bacsi4", args.attempts, stats)
        elif args.mode == "idor-probe":
            mode_idor_probe(args.base, demo_password(), args.user or "benhnhan1", args.max_id,
                            stats)
        else:
            mode_bulk_read(args.base, demo_password(), args.user or "bacsi1", args.records, stats)
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"simulate-traffic: {exc} (is the port-forward to {args.base} running?)",
              file=sys.stderr)
        return 1
    took = time.monotonic() - started
    print(f"{sum(stats.values())} requests in {took:.0f} s, by status: "
          + ", ".join(f"{k}: {v}" for k, v in sorted(stats.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
