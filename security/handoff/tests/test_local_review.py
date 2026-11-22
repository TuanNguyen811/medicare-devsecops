from local_review import pick_run


def run(rid: int, prs: list[int], path: str = ".github/workflows/pr-security.yml") -> dict:
    return {"id": rid, "path": path, "pull_requests": [{"number": n} for n in prs]}


def test_pick_run_takes_this_prs_latest_pr_security_run():
    runs = {"workflow_runs": [
        run(1, [19]), run(5, [19]), run(9, [20]),                 # same head in PR 20
        run(7, [19], path=".github/workflows/main-ci.yml"),       # another workflow
    ]}
    assert pick_run(runs, 19) == 5
    assert pick_run(runs, 21) is None
    assert pick_run({}, 19) is None
