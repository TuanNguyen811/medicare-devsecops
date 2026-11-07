from secagent.context.redact import REDACTED, mask_line, redact

# Fake secrets are assembled at runtime so no secret-shaped literal is ever committed.
AWS = "AKIA" + "Q" * 16
JWT = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12
GH = "ghp_" + "x" * 36
PEM_BODY = "MII" + "abcdef" * 4
PEM = ("-----BEGIN " + "RSA PRIVATE KEY-----\n" + PEM_BODY + "\n-----END " + "RSA PRIVATE KEY-----")
PW = "hun" + "ter2-real"
SK = "s3cr" + "3tvalue"


def test_redact_masks_secrets():
    text = "\n".join([
        f'aws = "{AWS}"',
        f"Authorization: Bearer {JWT}",
        f"clone with {GH}",
        PEM,
        f'DB_PASSWORD = "{PW}"',
        f"api_key: '{SK}'",
        f'{{"client_secret": "{SK}"}}',
        f'login(user, password="{PW}")',
    ])
    out = redact(text)
    for secret in (AWS, JWT, GH, PEM_BODY, PW, SK):
        assert secret not in out
    assert f'DB_PASSWORD = "{REDACTED}"' in out
    assert f"api_key: '{REDACTED}'" in out
    assert f'"client_secret": "{REDACTED}"' in out
    assert f'password="{REDACTED}"' in out


def test_redact_keeps_ordinary_code():
    code = (
        "def login(password: str = Form(...), db: Session = Depends(get_db)):\n"
        '    key = os.environ["SECRET_KEY"]\n'
        "    token = make_token(user)\n"
        '    if not secret_ok: raise ValueError("bad")\n'
    )
    assert redact(code) == code
    assert redact("") == ""


def test_mask_line_mentions_gitleaks():
    assert "Gitleaks" in mask_line() and REDACTED.strip("«»") in mask_line()


def test_redact_masks_dsn_and_provider_keys():
    pw = "Sup3r" + "Secret99"
    keys = ["sk-ant-" + "a1" * 20, "sk-proj-" + "b2" * 20, "sk-" + "c3d4" * 8,
            "sk_live_" + "Z" * 24, "xoxb-" + "1234567890-abcdefghij"]
    text = f"DSN = postgres://admin:{pw}@db:5432/medicare\n" + "\n".join(keys)
    out = redact(text)
    assert pw not in out and "postgres://admin:" in out and "@db:5432" in out
    for key in keys:
        assert key not in out
    assert redact("see https://user@example.com/a and http://h:8000/x") == (
        "see https://user@example.com/a and http://h:8000/x")
