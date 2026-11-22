"""Score the benchmark (spec 5.3, addendum 8.3-8.4) and write the result tables.

    uv run --project agent --with pyyaml==6.0.2 python benchmark/evaluate.py \\
        --scan <run> [--baseline-run <run holding S00>] --select test \\
        --configs C2,C3,C4,C5 --out benchmark/results/summary/test

Units and matching (addendum 8.4):
- C1 and C1+DAST predict every cluster of scanner findings the quality gate considers
  (clusters.json from run.py fetch). An agent run predicts each report entry whose verdict is
  TP. NEEDS_REVIEW is never a detection: the strict view counts it as an FP, the lenient view
  ignores it (spec 5.3).
- A prediction matches a ground-truth vulnerability when one of its locations is in the same
  file with lines within +-3 of the vulnerable range and in the same CWE family (or names one
  of its scanner `rules`, or, for an agent finding, one of the business rules R-xx the bug
  violates: the CWE of a logic bug is a matter of judgement, the broken rules are listed in
  the ground truth); a DAST prediction matches on route (`METHOD /template`) and family.
- TP: vulnerabilities matched by at least one prediction (several tools reporting the same bug
  count once). FP: predictions matching no vulnerability. FN: vulnerabilities left unmatched.
- Scanner findings in a file the PR changed but entirely on lines it did not add (e.g. the
  existing Checkov findings of main.tf when a PR adds a bucket to it) score as usual (FP when
  they match no vulnerability) and are also counted apart, so the FP reduction is not
  overstated.
- ZAP findings of the unchanged baseline S00 (same ZAP rule) are pre-existing issues of the
  running app, reported again in every scenario: neither TP nor FP, counted apart.
- Every expected (scenario x repetition) of a config is scored. A failed or missing agent run
  detects nothing, and at PR level the gate falls back to traditional mode, as in the pipeline.
- PR level: the quality gate decision (traditional for C1/C1+DAST, ai-assisted with the agent's
  report.json) should block a vulnerable scenario and let a decoy or the baseline through.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import scenario as sc
import yaml
from run import RESULTS, _load_gate
from secagent.context.sarif import cwe_group

SCAN_VIEWS = ("C1", "C1+DAST")
LINE_SLACK = 3
EXPECT_BLOCK = {"vuln", "robustness"}

Span = tuple[str, int, int]  # (file or "dast:METHOD /route", start line, end line)


@dataclass(frozen=True)
class Truth:
    id: str
    scenario: str
    title: str
    category: str  # pattern | logic
    cwes: frozenset[str]
    file: str
    start: int
    end: int
    routes: frozenset[str] = frozenset()
    rules: frozenset[str] = frozenset()
    violated_rules: frozenset[str] = frozenset()


@dataclass
class Prediction:
    spans: list[Span]
    cwes: set[str] = field(default_factory=set)
    rules: set[str] = field(default_factory=set)
    needs_review: bool = False
    violated_rule: str | None = None

    @property
    def runtime(self) -> bool:
        return any(f.startswith("dast:") for f, _, _ in self.spans)


def _rule_set(value) -> frozenset[str]:
    """`violated_rule` in ground_truth.yaml: null, one rule, or a list of rules."""
    if not value:
        return frozenset()
    return frozenset([value] if isinstance(value, str) else value)


def load_truth(scenario: sc.Scenario) -> list[Truth]:
    data = yaml.safe_load((scenario.dir / "ground_truth.yaml").read_text(encoding="utf-8"))
    out = []
    for item in (data or {}).get("findings") or []:
        lines = item.get("lines") or [item["line"], item["line"]]
        out.append(Truth(
            id=item["id"], scenario=scenario.id, title=item["title"],
            category=item["category"], cwes=frozenset(item["cwe"]), file=item["file"],
            start=int(lines[0]), end=int(lines[-1]),
            routes=frozenset(item.get("routes") or []),
            rules=frozenset(item.get("rules") or []),
            violated_rules=_rule_set(item.get("violated_rule"))))
    return out


def _families(cwes) -> set[str]:
    return {cwe_group(c) for c in cwes}


def matches(p: Prediction, t: Truth) -> bool:
    same_family = bool(_families(p.cwes) & _families(t.cwes))
    same_rule = p.violated_rule is not None and p.violated_rule in t.violated_rules
    for file, start, end in p.spans:
        if file.startswith("dast:"):
            if file.removeprefix("dast:") in t.routes and same_family:
                return True
        elif (file == t.file and start - LINE_SLACK <= t.end and end + LINE_SLACK >= t.start
              and (same_family or same_rule or bool(p.rules & t.rules))):
            return True
    return False


Known = frozenset[str]  # ZAP rule ids already reported on the baseline S00


def baseline_dast(clusters: list[dict]) -> Known:
    """ZAP rules of the unchanged baseline: ZAP scans the whole running app, so the same
    checks (missing headers…) fire in every scenario, on whatever pages the spider reaches."""
    return frozenset(r for c in clusters if c["file"].startswith("dast:") for r in c["rules"])


def is_known(p: Prediction, known: Known) -> bool:
    return p.runtime and bool(p.rules & known)


Added = sc.Added


def on_old_code(p: Prediction, added: Added) -> bool:
    """Every location is on a line the PR did not add (pre-existing code)."""
    if p.runtime:
        return False
    return all(not (added.get(f, set()) & set(range(start, end + 1))) for f, start, end in p.spans)


@dataclass
class Score:
    tp: set[str] = field(default_factory=set)
    fp: int = 0
    fn: set[str] = field(default_factory=set)
    known: int = 0  # pre-existing baseline DAST findings reported again
    needs_review: int = 0
    fp_old: int = 0  # FPs located only on code the PR did not add


def score(predictions: list[Prediction], truths: list[Truth], strict: bool,
          known: Known = frozenset(), added: Added | None = None) -> Score:
    s = Score()

    def false_positive(p: Prediction) -> None:
        s.fp += 1
        if added is not None and on_old_code(p, added):
            s.fp_old += 1

    for p in predictions:
        if p.needs_review:
            s.needs_review += 1
            if strict and not is_known(p, known):
                false_positive(p)  # spec 5.3: NEEDS_REVIEW counts as an FP in the strict view
            continue
        hit = [t.id for t in truths if matches(p, t)]
        if hit:
            s.tp.update(hit)
        elif is_known(p, known):
            s.known += 1
        else:
            false_positive(p)
    s.fn = {t.id for t in truths} - s.tp
    return s


def scanner_predictions(clusters: list[dict]) -> list[Prediction]:
    return [Prediction([(c["file"], c["line"], c["end_line"])], set(c["cwes"]), set(c["rules"]))
            for c in clusters]


def agent_predictions(report: dict, clusters: list[dict]) -> list[Prediction]:
    by_finding = {fid: c for c in clusters for fid in c["finding_ids"]}
    out = []
    for e in report.get("findings") or []:
        if e.get("verdict") not in ("TP", "NEEDS_REVIEW"):
            continue
        cluster = next((by_finding[f] for f in e.get("finding_ids") or [] if f in by_finding),
                       None)
        cwes = {e["cwe"]} if e.get("cwe") else set()
        if cluster is not None:  # a judged scanner cluster: its location and families
            p = Prediction([(cluster["file"], cluster["line"], cluster["end_line"])],
                           cwes | set(cluster["cwes"]), set(cluster["rules"]))
        else:  # a vulnerability the agent found itself: every place its evidence points to
            spans = [(ev.get("file") or "", int(ev.get("start_line") or 0),
                      int(ev.get("end_line") or ev.get("start_line") or 0))
                     for ev in e.get("evidence") or []]
            p = Prediction(spans or [(e.get("file") or "", int(e.get("line") or 0),
                                      int(e.get("line") or 0))], cwes)
        p.needs_review = e["verdict"] == "NEEDS_REVIEW"
        p.violated_rule = e.get("violated_rule") or None
        out.append(p)
    return out


# --- collection ---------------------------------------------------------------------------------


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class EvaluateError(Exception):
    pass


def _truth_dicts(truths: dict[str, list[Truth]]) -> dict[str, list[dict]]:
    return {k: [t.__dict__ | {"cwes": sorted(t.cwes), "routes": sorted(t.routes),
                              "rules": sorted(t.rules),
                              "violated_rules": sorted(t.violated_rules)} for t in v]
            for k, v in truths.items()}


def collect(scan: Path, baseline: Path, scenarios: list[sc.Scenario], configs: list[str],
            gate) -> dict:
    """One scored row per C1/C1+DAST scenario and per expected (config, scenario, rep)."""
    truths = {s.id: load_truth(s) for s in scenarios}
    ids = [t.id for ts in truths.values() for t in ts]
    if len(ids) != len(set(ids)):
        raise EvaluateError("ground-truth ids must be unique across scenarios")
    s00 = baseline / sc.BASELINE / "clusters.json"
    if not s00.is_file():
        raise EvaluateError(f"no S00 scan in {baseline}: pass --baseline-run")
    known = baseline_dast(_read(s00)["C1+DAST"])
    rows, versions = [], {}
    runs = {c: RESULTS / "runs" / scan.name / c for c in configs}
    reps = {c: sorted({int(d.name[3:]) for d in runs[c].glob("*/rep*")}) for c in configs}
    for s in scenarios:
        views = _read(scan / s.id / "clusters.json")
        gate_view = _read(scan / s.id / "gate.json")
        for view in SCAN_VIEWS:
            rows.append(_row(view, s, 1, scanner_predictions(views[view]), truths[s.id],
                             gate_view[view]["block"], None, known))
        gf = _read(scan / s.id / "gate_findings.json")["C1+DAST"]
        relevant = [SimpleNamespace(**f) for f in gf["findings"]]
        changed = set(_read(scan / s.id / "changed.json"))
        for config in configs:
            for rep in reps[config]:
                rundir = runs[config] / s.id / f"rep{rep}"
                timing = _read(rundir / "timing.json") if (rundir / "timing.json").is_file() \
                    else {}
                if timing.get("exit") != 0 or not (rundir / "report.json").is_file():
                    # The agent failed: nothing detected; the gate falls back to traditional.
                    row = _row(config, s, rep, [], truths[s.id],
                               gate_view["C1+DAST"]["block"], None, known)
                    row["failed"] = True
                    rows.append(row)
                    continue
                versions.setdefault(config, set()).add(
                    (timing.get("agent_commit"), bool(timing.get("agent_dirty"))))
                report = _read(rundir / "report.json")
                decision = gate.decide(relevant, mode="ai-assisted", report=report,
                                       labels=set(), agent_exit=0, errors=gf["errors"],
                                       changed=changed)
                row = _row(config, s, rep, agent_predictions(report, views["C1+DAST"]),
                           truths[s.id], decision.block, report, known)
                row["wall_s"] = timing.get("wall_s")
                rows.append(row)
    for config, seen in versions.items():
        if len({commit for commit, _ in seen}) > 1:
            raise EvaluateError(f"{config}: runs from different agent versions {sorted(seen)}")
    return {"rows": rows, "truths": _truth_dicts(truths),
            "agent_versions": {c: sorted(map(list, v)) for c, v in versions.items()}}


def _row(config: str, s: sc.Scenario, rep: int, preds: list[Prediction], truths: list[Truth],
         blocked: bool, report: dict | None, known: Known = frozenset()) -> dict:
    added = sc.added_lines(s.patch_text())
    strict = score(preds, truths, True, known, added)
    lenient = score(preds, truths, False, known)
    row = {"config": config, "scenario": s.id, "kind": s.kind, "split": s.split, "rep": rep,
           "truths": len(truths), "tp": sorted(strict.tp), "fp": strict.fp,
           "fn": sorted(strict.fn), "fp_lenient": lenient.fp, "known": strict.known,
           "needs_review": strict.needs_review, "fp_old": strict.fp_old, "blocked": blocked,
           "gate_ok": blocked == (s.kind in EXPECT_BLOCK), "failed": False}
    if report is not None:
        meta = report.get("meta") or {}
        row.update({k: meta.get(k) for k in ("provider", "model", "duration_s", "llm_calls",
                                             "tool_calls", "tokens_in", "tokens_out",
                                             "cost_usd", "limit_hit")})
        row["degraded"] = bool(meta.get("error"))  # ran out of time or failed midway
    return row


# --- aggregation and tables ---------------------------------------------------------------------


def _prf(tp: int, fp: int, fn: int) -> tuple[float | None, float | None, float | None]:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return p, r, f1


def summarize(data: dict) -> dict:
    rows = data["rows"]
    truths = {t["id"]: t for ts in data["truths"].values() for t in ts}
    c1 = {t for r in rows if r["config"] == "C1" for t in r["tp"]}
    c1dast = {t for r in rows if r["config"] == "C1+DAST" for t in r["tp"]}

    def measured(tid: str) -> str:
        return "sast_sca" if tid in c1 else ("dast_only" if tid in c1dast else "neither")

    out = {}
    for config in dict.fromkeys(r["config"] for r in rows):
        mine = [r for r in rows if r["config"] == config]
        reps = sorted({r["rep"] for r in mine})
        per_rep = []
        for rep in reps:
            rr = [r for r in mine if r["rep"] == rep]
            tp = sum(len(r["tp"]) for r in rr)
            fn = sum(r["truths"] for r in rr) - tp
            for view, fp_key in (("strict", "fp"), ("lenient", "fp_lenient")):
                fp = sum(r[fp_key] for r in rr)
                p, rec, f1 = _prf(tp, fp, fn)
                per_rep.append({"rep": rep, "view": view, "tp": tp, "fp": fp, "fn": fn,
                                "precision": p, "recall": rec, "f1": f1})
        groups: dict[str, list[bool]] = {}
        for tid, t in truths.items():
            hits = [tid in r["tp"] for r in mine if r["scenario"] == t["scenario"]]
            groups.setdefault(f"category:{t['category']}", []).extend(hits)
            groups.setdefault(f"measured:{measured(tid)}", []).extend(hits)
        no_bug = [r for r in mine if r["kind"] in ("decoy", "baseline")]
        ran = [r for r in mine if not r["failed"] and r.get("cost_usd") is not None]
        out[config] = {
            "reps": len(reps), "per_rep": per_rep,
            "recall_by_group": {k: (sum(v) / len(v) if v else None, len(v))
                                for k, v in sorted(groups.items())},
            "fp_on_clean": [sum(r["fp"] for r in no_bug if r["rep"] == rep) for rep in reps],
            "vuln_blocked": sum(r["blocked"] for r in mine if r["kind"] in EXPECT_BLOCK),
            "vuln_total": sum(1 for r in mine if r["kind"] in EXPECT_BLOCK),
            "clean_passed": sum(not r["blocked"] for r in mine
                                if r["kind"] not in EXPECT_BLOCK),
            "clean_total": sum(1 for r in mine if r["kind"] not in EXPECT_BLOCK),
            "detection": {tid: [sum(tid in r["tp"] for r in mine
                                    if r["scenario"] == t["scenario"]),
                                sum(1 for r in mine if r["scenario"] == t["scenario"])]
                          for tid, t in truths.items()},
            "failed_runs": sum(r["failed"] for r in mine),
            "degraded_runs": sum(bool(r.get("degraded")) for r in mine),
            "known": sum(r["known"] for r in mine),
            "fp_old": sum(r.get("fp_old", 0) for r in mine),
            "needs_review": sum(r["needs_review"] for r in mine),
        }
        if ran:
            out[config]["cost"] = {k: statistics.mean(r.get(k) or 0 for r in ran)
                                   for k in ("duration_s", "wall_s", "llm_calls", "tool_calls",
                                             "tokens_in", "tokens_out", "cost_usd")}
            out[config]["model"] = sorted({f"{r.get('provider')}/{r.get('model')}"
                                           for r in ran})
    return out


def _mean(values: list) -> str:
    values = [v for v in values if v is not None]
    if not values:
        return "-"
    if len(values) == 1:
        return f"{values[0]:.2f}"
    return f"{statistics.mean(values):.2f} ± {statistics.pstdev(values):.2f}"


def render(summary: dict, data: dict) -> str:
    lines = ["# Kết quả benchmark", "",
             "Chấm theo spec gốc mục 5.3 và spec bổ sung mục 8.4. Ô có ± là trung bình ± độ "
             "lệch chuẩn qua các lần chạy; `-` là không xác định (không có dự đoán nào).",
             "", "## Độ chính xác", "",
             "Chặt: NEEDS_REVIEW tính là FP. Lỏng: bỏ qua NEEDS_REVIEW. TP, FN và recall "
             "như nhau ở hai cách.", "",
             ("| Cấu hình | LLM | Lần chạy | TP | FN | FP (chặt) | Precision (chặt) | Recall | "
              "F1 (chặt) | FP (lỏng) | F1 (lỏng) |"),
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for config, s in summary.items():
        strict = [r for r in s["per_rep"] if r["view"] == "strict"]
        lenient = [r for r in s["per_rep"] if r["view"] == "lenient"]
        lines.append(
            f"| {config} | {', '.join(s.get('model', ['—']))} | {s['reps']} | "
            f"{_mean([r['tp'] for r in strict])} | {_mean([r['fn'] for r in strict])} | "
            f"{_mean([r['fp'] for r in strict])} | {_mean([r['precision'] for r in strict])} | "
            f"{_mean([r['recall'] for r in strict])} | {_mean([r['f1'] for r in strict])} | "
            f"{_mean([r['fp'] for r in lenient])} | {_mean([r['f1'] for r in lenient])} |")
    groups = sorted({g for s in summary.values() for g in s["recall_by_group"]})
    lines += ["", "## Recall theo nhóm lỗ hổng", ""]
    if groups:
        lines += ["| Cấu hình | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
        for config, s in summary.items():
            cells = []
            for g in groups:
                value, n = s["recall_by_group"].get(g, (None, 0))
                cells.append("-" if value is None else f"{value:.2f} (n={n})")
            lines.append(f"| {config} | " + " | ".join(cells) + " |")
        lines += ["", ("`measured:sast_sca`: C1 bắt được; `measured:dast_only`: chỉ ZAP bắt "
                       "được; `measured:neither`: không công cụ nào bắt được.")]
    else:
        lines.append("(các kịch bản được chọn không có lỗ hổng nào)")
    lines += ["", "## Quyết định của quality gate (cấp PR) và các lần chạy", "",
              ("Phát hiện ZAP đã có trên bản gốc S00 (cùng rule ZAP) là vấn đề có sẵn của app "
               "đang chạy, không do PR gây ra: không tính TP hay FP, đếm ở cột riêng. "
               "\"FP ở code có sẵn\": số FP (chấm chặt, cộng mọi lần chạy) chỉ nằm trên dòng PR "
               "không thêm, trong file PR có sửa; đã tính trong cột FP ở trên."), "",
              ("| Cấu hình | PR có lỗ hổng bị chặn | PR sạch / mồi nhử được qua | "
               "FP trên PR sạch (mỗi lần chạy) | FP ở code có sẵn | Phát hiện DAST có sẵn | "
               "NEEDS_REVIEW | Lần chạy lỗi | Lần chạy dở dang |"),
              "|---|---|---|---|---|---|---|---|---|"]
    for config, s in summary.items():
        lines.append(f"| {config} | {s['vuln_blocked']}/{s['vuln_total']} | "
                     f"{s['clean_passed']}/{s['clean_total']} | "
                     f"{', '.join(map(str, s['fp_on_clean']))} | {s['fp_old']} | "
                     f"{s['known']} | "
                     f"{s['needs_review']} | {s['failed_runs']} | {s['degraded_runs']} |")
    costly = {c: s for c, s in summary.items() if "cost" in s}
    if costly:
        lines += ["", "## Chi phí mỗi PR (trung bình, lần chạy thành công)", "",
                  ("| Cấu hình | Thời gian agent (s) | Thời gian cả lượt (s) | Lượt gọi LLM | "
                   "Lượt gọi công cụ | Token vào | Token ra | Chi phí quy đổi (USD) |"),
                  "|---|---|---|---|---|---|---|---|"]
        for config, s in costly.items():
            c = s["cost"]
            lines.append(f"| {config} | {c['duration_s']:.1f} | {c['wall_s']:.1f} | "
                         f"{c['llm_calls']:.1f} | {c['tool_calls']:.1f} | {c['tokens_in']:.0f} "
                         f"| {c['tokens_out']:.0f} | {c['cost_usd']:.4f} |")
    truths = [t for ts in data["truths"].values() for t in ts]
    if truths:
        lines += ["", "## Từng lỗ hổng: số lần được phát hiện / số lần chạy", "",
                  "| Lỗ hổng | Nhóm | " + " | ".join(summary) + " |",
                  "|---|---|" + "---|" * len(summary)]
        for t in truths:
            cells = ["{}/{}".format(*s["detection"].get(t["id"], [0, 0]))
                     for s in summary.values()]
            lines.append(f"| {t['id']} {t['title']} | {t['category']} | " + " | ".join(cells)
                         + " |")
    versions = data.get("agent_versions") or {}
    if versions:
        lines += ["", "Phiên bản agent (hash cây `agent/`, có thay đổi chưa commit): "
                  + "; ".join(f"{c}: {v}" for c, v in versions.items())]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scan", required=True, help="fetched scan run id")
    ap.add_argument("--baseline-run", help="scan run holding S00 (default: --scan)")
    ap.add_argument("--select", default="test")
    ap.add_argument("--configs", default="C2,C3,C4,C5")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    scan = RESULTS / "scans" / args.scan
    baseline = RESULTS / "scans" / (args.baseline_run or args.scan)
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    try:
        data = collect(scan, baseline, sc.select(args.select), configs, _load_gate())
    except (EvaluateError, sc.ScenarioError) as exc:
        print(f"evaluate: {exc}", file=sys.stderr)
        return 2
    summary = summarize(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "rows.json").write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                        encoding="utf-8")
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False),
                                           encoding="utf-8")
    (args.out / "results.md").write_text(render(summary, data), encoding="utf-8")
    print(f"evaluate: {args.out / 'results.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
