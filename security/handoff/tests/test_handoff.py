import base64
import gzip
import json
import os
from pathlib import Path

import pytest
from handoff import MAX_COMMENT, HandoffError, marker, pack, parse_comments, unpack, wait

SHA = "a" * 40
REPORT = json.dumps({"meta": {"provider": "claude-mcp"}, "findings": []})


def files(**extra) -> dict[str, str]:
    return {"report.json": REPORT, "report.md": "# secagent\n", **extra}


def body_with(payload, sha: str = SHA, raw: bytes | None = None) -> str:
    data = raw if raw is not None else gzip.compress(json.dumps(payload).encode())
    blob = base64.b64encode(data).decode()
    return f"{marker(sha)}\n\n```\n{blob}\n```\n"


def test_pack_round_trips_and_reads_only_known_files(tmp_path: Path):
    for name, text in files(**{"review.json": "{}", "agent.sarif": "{}"}).items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    (tmp_path / "trace.jsonl").write_text("local only", encoding="utf-8")
    body = pack(tmp_path, SHA)
    assert body.startswith(marker(SHA))
    got = unpack(body, SHA)
    assert set(got) == {"report.json", "report.md", "review.json", "agent.sarif"}
    assert got["report.json"] == REPORT


def test_pack_drops_agent_sarif_rather_than_the_report(tmp_path: Path):
    (tmp_path / "report.json").write_text(REPORT, encoding="utf-8")
    (tmp_path / "agent.sarif").write_text(os.urandom(60_000).hex(), encoding="utf-8")
    body = pack(tmp_path, SHA)
    assert len(body) <= MAX_COMMENT and set(unpack(body, SHA)) == {"report.json"}


def test_pack_needs_a_report(tmp_path: Path):
    with pytest.raises(HandoffError):
        pack(tmp_path, SHA)


@pytest.mark.parametrize("payload", [
    files(**{"../evil.sh": "x"}),                # only known file names
    files(**{"report.json": "not json"}),        # report.json must parse
    files(**{"report.json": json.dumps({"meta": {}})}),  # with a findings list
    {"report.md": "no report.json"},
    ["not", "a", "dict"],
    files(**{"report.md": 42}),                  # values are text
])
def test_unpack_rejects_bad_payloads(payload):
    with pytest.raises(HandoffError):
        unpack(body_with(payload), SHA)


@pytest.mark.parametrize("raw", [
    gzip.compress(json.dumps(files()).encode())[:-12],               # truncated stream
    b"not gzip at all",
    gzip.compress(("[" * 100_000 + "]" * 100_000).encode()),        # deep nesting
    gzip.compress(b"9" * 5000),                                     # huge integer
])
def test_unpack_rejects_unreadable_payloads(raw):
    with pytest.raises(HandoffError):
        unpack(body_with(None, raw=raw), SHA)


def test_unpack_rejects_bad_base64_and_misplaced_markers():
    good = body_with(files())
    with pytest.raises(HandoffError):
        unpack(good.replace("```\n", "```\n!!", 1), SHA)
    for body in ("> " + good, "note\n" + good, good.replace("\n", "\r\n")):
        with pytest.raises(HandoffError):
            unpack(body, SHA)


def test_unpack_rejects_another_commit():
    with pytest.raises(HandoffError):
        unpack(body_with(files(), sha="b" * 40), SHA)


def test_unpack_rejects_oversized_payload():
    big = files(**{"report.md": "x" * 3_000_000})
    with pytest.raises(HandoffError):
        unpack(body_with(big), SHA)


def comment(login: str, body: str, cid: int = 1, edited: bool = False) -> dict:
    return {"id": cid, "login": login, "body": body, "edited": edited}


def test_wait_takes_only_the_trusted_authors_latest_handoff(tmp_path: Path):
    forged = body_with(files(**{"report.md": "forged"}))
    old = body_with(files(**{"report.md": "old"}))
    new = body_with(files(**{"report.md": "new"}))
    comments = [comment("mallory", forged, 1), comment("owner", old, 2),
                comment("owner", "just a remark", 3), comment("owner", new, 4),
                comment("mallory", forged, 5)]
    code = wait(lambda: comments, SHA, "owner", tmp_path, timeout_s=0, sleep=lambda _: None)
    assert code == 0
    assert (tmp_path / "report.md").read_text(encoding="utf-8") == "new"


def test_wait_ignores_an_edited_comment_of_the_trusted_author(tmp_path: Path):
    """Anyone with write access can edit the reviewer's comment; it keeps its author."""
    forged = body_with(files(**{"report.md": "forged"}))
    code = wait(lambda: [comment("owner", forged, 7, edited=True)], SHA, "owner", tmp_path,
                timeout_s=0)
    assert code == 2 and not (tmp_path / "report.md").exists()


def test_parse_comments_reads_the_graphql_answer():
    user = {"__typename": "User", "login": "owner"}
    data = {"data": {"repository": {"pullRequest": {"comments": {"nodes": [
        {"databaseId": 1, "body": "a", "lastEditedAt": None, "author": user},
        {"databaseId": 2, "body": "b", "lastEditedAt": "2026-11-22T10:00:00Z", "author": user},
        {"databaseId": 3, "body": "c", "lastEditedAt": None, "author": None},
        {"databaseId": 4, "body": "d", "lastEditedAt": None,  # a bot named like the reviewer
         "author": {"__typename": "Bot", "login": "owner"}},
    ]}}}}}
    assert parse_comments(data) == [
        {"id": 1, "login": "owner", "body": "a", "edited": False},
        {"id": 2, "login": "owner", "body": "b", "edited": True},
        {"id": 3, "login": None, "body": "c", "edited": False},
        {"id": 4, "login": None, "body": "d", "edited": False}]


def test_wait_times_out_without_a_trusted_handoff(tmp_path: Path):
    polls = []

    def fetch():
        polls.append(1)
        return [comment("mallory", body_with(files()))]

    clock = iter(range(0, 1000, 30))
    code = wait(fetch, SHA, "owner", tmp_path, timeout_s=90, sleep=lambda _: None,
                clock=lambda: next(clock))
    assert code == 2 and len(polls) >= 2
    assert not (tmp_path / "report.json").exists()


def test_wait_without_a_configured_author_fails_at_once(tmp_path: Path):
    assert wait(lambda: pytest.fail("must not poll"), SHA, "", tmp_path, timeout_s=900) == 2


def test_wait_stops_on_an_invalid_trusted_handoff(tmp_path: Path):
    bad = body_with({"report.md": "no report.json"})
    assert wait(lambda: [comment("owner", bad)], SHA, "owner", tmp_path, timeout_s=0) == 2
