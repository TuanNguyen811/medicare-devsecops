import base64
import gzip
import json
from pathlib import Path

import pytest
from handoff import HandoffError, marker, pack, unpack, wait

SHA = "a" * 40
REPORT = json.dumps({"meta": {"provider": "claude-mcp"}, "findings": []})


def files(**extra) -> dict[str, str]:
    return {"report.json": REPORT, "report.md": "# secagent\n", **extra}


def body_with(payload: dict, sha: str = SHA) -> str:
    blob = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
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


def test_pack_needs_a_report(tmp_path: Path):
    with pytest.raises(HandoffError):
        pack(tmp_path, SHA)


@pytest.mark.parametrize("payload", [
    files(**{"../evil.sh": "x"}),                # only known file names
    files(**{"report.json": "not json"}),        # report.json must parse
    files(**{"report.json": json.dumps({"meta": {}})}),  # with a findings list
    {"report.md": "no report.json"},
    ["not", "a", "dict"],
])
def test_unpack_rejects_bad_payloads(payload):
    with pytest.raises(HandoffError):
        unpack(body_with(payload), SHA)


def test_unpack_rejects_another_commit():
    with pytest.raises(HandoffError):
        unpack(body_with(files(), sha="b" * 40), SHA)


def test_unpack_rejects_oversized_payload():
    big = files(**{"report.md": "x" * 3_000_000})
    with pytest.raises(HandoffError):
        unpack(body_with(big), SHA)


def comment(login: str, body: str, cid: int = 1) -> dict:
    return {"id": cid, "login": login, "body": body}


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
