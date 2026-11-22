"""Score the benchmark (spec 5.3, addendum 8.3-8.4) and write the result tables.

    uv run --project agent --with pyyaml==6.0.2 python benchmark/evaluate.py \\
        --scan <run> --select test --configs C2,C3,C4,C5 --out benchmark/results/summary/test

Units and matching:
- C1 and C1+DAST predict every cluster of scanner findings the quality gate considers
  (clusters.json from run.py fetch). An agent run predicts each report entry whose verdict is
  TP; NEEDS_REVIEW counts as a positive in the strict view and is ignored in the lenient one.
- A prediction matches a ground-truth vulnerability when it is in the same file with lines
  within +-3 of the vulnerable range and in the same CWE family (or names one of its scanner
  `rules`); a DAST prediction matches on route (`METHOD /template`) and CWE family.
- TP: vulnerabilities matched by at least one prediction (several tools reporting the same bug
  count once). FP: predictions matching no vulnerability. FN: vulnerabilities left unmatched.
- PR level: the quality gate decision (traditional for C1/C1+DAST, ai-assisted with the agent's
  report.json) should block a vulnerable scenario and let a decoy or the baseline through.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from types import SimpleNamespace
from pathlib import Path

import scenario as sc
import yaml
from run import RESULTS, _load_gate
from secagent.context.sarif import cwe_group

SCAN_VIEWS = ("C1", "C1+DAST")
LINE_SLACK = 3
EXPECT_BLOCK = {"vuln", "robustness"}


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


@dataclass
class Prediction:
    file: str
    start: int
    end: int
    cwes: set[str] = field(default_factory=set)
    rules: set[str] = field(default_factory=set)
    strict_only: bool = False  # NEEDS_REVIEW


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
            rules=frozenset(item.get("rules") or [])))
    return out


def _families(cwes) -> set[str]:
    return {cwe_group(c) for c in cwes}


def matches(p: Prediction, t: Truth) -> bool:
    if p.file.startswith("dast:"):
        return p.file.removeprefix("dast:") in t.routes and bool(_families(p.cwes)
                                                                  & _families(t.cwes))
    if p.file != t.file or p.end < t.start - LINE_SLACK or p.start > t.end + LINE_SLACK:
        return False
    return bool(_families(p.cwes) & _families(t.cwes)) or bool(p.rules & t.rules)


@dataclass
class Score:
    tp: set[str] = field(default_factory=set)
    fp: int = 0
    fn: set[str] = field(default_factory=set)
    known: int = 0  # pre-existing baseline DAST findings reported again


Known = frozenset[tuple[str, str]]  # (route, CWE family) that ZAP already reports on S00


def baseline_dast(clusters: list[dict]) -> Known:
    """Runtime findings of the unchanged baseline (S00): ZAP scans the whole running app, so
    they show up in every scenario; they are pre-existing issues, not caused by the PR."""
    return frozenset((c["file"].removeprefix("dast:"), fam) for c in clusters
                     if c["file"].startswith("dast:") for fam in _families(c["cwes"]))


def is_known(p: Prediction, known: Known) -> bool:
    route = p.file.removeprefix("dast:")
    return p.file.startswith("dast:") and any((route, f) in known for f in _families(p.cwes))


def score(predictions: list[Prediction], truths: list[Truth], strict: bool,
          known: Known = frozenset()) -> Score:
    """A prediction matching no vulnerability is an FP, unless it is a pre-existing baseline
    DAST finding (counted apart in `known`)."""
    s = Score()
    for p in predictions:
        if p.strict_only and not strict:
            continue
        hit = [t.id for t in truths if matches(p, t)]
        if hit:
            s.tp.update(hit)
        elif is_known(p, known):
            s.known += 1
        else:
            s.fp += 1
    s.fn = {t.id for t in truths} - s.tp
    return s


def scanner_predictions(clusters: list[dict]) -> list[Prediction]:
    return [Prediction(c["file"], c["line"], c["end_line"], set(c["cwes"]), set(c["rules"]))
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
            p = Prediction(cluster["file"], cluster["line"], cluster["end_line"],
                           cwes | set(cluster["cwes"]), set(cluster["rules"]))
        else:  # a vulnerability the agent found itself: where its evidence points
            ev = (e.get("evidence") or [{}])[0]
            start = int(ev.get("start_line") or e.get("line") or 0)
            p = Prediction(ev.get("file") or e.get("file") or "", start,
                           int(ev.get("end_line") or start), cwes)
        p.strict_only = e["verdict"] == "NEEDS_REVIEW"
        out.append(p)
    return out


# --- collection ---------------------------------------------------------------------------------


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect(scan: Path, scenarios: list[sc.Scenario], configs: list[str], gate) -> dict:
    """Every scored observation: one per (config, scenario, rep)."""
    rows = []
    truths = {s.id: load_truth(s) for s in scenarios}
    baseline = scan / sc.BASELINE / "clusters.json"
    known = baseline_dast(_read(baseline)["C1+DAST"]) if baseline.is_file() else frozenset()
    for s in scenarios:
        views = _read(scan / s.id / "clusters.json")
        gate_view = _read(scan / s.id / "gate.json")
        for view in SCAN_VIEWS:
            preds = scanner_predictions(views[view])
            rows.append(_row(view, s, 1, preds, truths[s.id], gate_view[view]["block"], None,
                             known))
        gf = _read(scan / s.id / "gate_findings.json")["C1+DAST"]
        relevant = [SimpleNamespace(**f) for f in gf["findings"]]
        errors = gf["errors"]
        changed = set(_read(scan / s.id / "changed.json"))
        for config in configs:
            base = RESULTS / "runs" / config / s.id
            for rundir in sorted(base.glob("rep*")) if base.is_dir() else []:
                timing = _read(rundir / "timing.json") if (rundir / "timing.json").is_file() \
                    else {}
                if timing.get("exit") != 0:
                    rows.append({"config": config, "scenario": s.id,
                                 "rep": int(rundir.name[3:]), "failed": True})
                    continue
                report = _read(rundir / "report.json")
                decision = gate.decide(relevant, mode="ai-assisted", report=report,
                                       labels=set(), agent_exit=0, errors=errors,
                                       changed=changed)
                preds = agent_predictions(report, views["C1+DAST"])
                row = _row(config, s, int(rundir.name[3:]), preds, truths[s.id],
                           decision.block, report, known)
                row["wall_s"] = timing.get("wall_s")
                rows.append(row)
    return {"rows": rows, "truths": {k: [t.__dict__ | {"cwes": sorted(t.cwes),
                                                       "routes": sorted(t.routes),
                                                       "rules": sorted(t.rules)}
                                         for t in v] for k, v in truths.items()}}


def _row(config: str, s: sc.Scenario, rep: int, preds: list[Prediction], truths: list[Truth],
         blocked: bool, report: dict | None, known: Known = frozenset()) -> dict:
    strict = score(preds, truths, True, known)
    lenient = score(preds, truths, False, known)
    row = {"config": config, "scenario": s.id, "kind": s.kind, "split": s.split, "rep": rep,
           "tp": sorted(strict.tp), "fp": strict.fp, "fn": sorted(strict.fn),
           "tp_lenient": sorted(lenient.tp), "fp_lenient": lenient.fp, "known": strict.known,
           "blocked": blocked, "gate_ok": blocked == (s.kind in EXPECT_BLOCK)}
    if report is not None:
        meta = report.get("meta") or {}
        row.update({k: meta.get(k) for k in ("provider", "model", "duration_s", "llm_calls",
                                             "tool_calls", "tokens_in", "tokens_out",
                                             "cost_usd", "limit_hit")})
        fixes = [e.get("fix") for e in report.get("findings") or []
                 if e.get("verdict") == "TP" and e.get("fix") and e["fix"].get("patch")]
        row["patches"] = len(fixes)
        row["patches_validated"] = sum(1 for f in fixes if f.get("validated") is True)
        row["patches_failed"] = sum(1 for f in fixes if f.get("validated") is False)
    return row


# --- aggregation and tables ---------------------------------------------------------------------


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def summarize(data: dict) -> dict:
    rows = [r for r in data["rows"] if not r.get("failed")]
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
            for view, tp_key, fp_key in (("strict", "tp", "fp"),
                                         ("lenient", "tp_lenient", "fp_lenient")):
                tp = sum(len(r[tp_key]) for r in rr)
                fp = sum(r[fp_key] for r in rr)
                fn = sum(len(truths_of(data, r["scenario"])) for r in rr) - tp
                p, rec, f1 = _prf(tp, fp, fn)
                per_rep.append({"rep": rep, "view": view, "tp": tp, "fp": fp, "fn": fn,
                                "precision": p, "recall": rec, "f1": f1})
        groups = {}
        for key in ("category", "measured"):
            for tid, t in truths.items():
                label = t["category"] if key == "category" else measured(tid)
                hits = [tid in r["tp"] for r in mine if r["scenario"] == t["scenario"]]
                groups.setdefault(f"{key}:{label}", []).extend(hits)
        no_bug = [r for r in mine if r["kind"] in ("decoy", "baseline")]
        out[config] = {
            "reps": len(reps), "per_rep": per_rep,
            "recall_by_group": {k: (sum(v) / len(v) if v else None, len(v))
                                for k, v in sorted(groups.items())},
            "fp_on_clean": [sum(r["fp"] for r in no_bug if r["rep"] == rep) for rep in reps],
            "gate_ok": sum(r["gate_ok"] for r in mine), "gate_total": len(mine),
            "vuln_blocked": sum(r["blocked"] for r in mine if r["kind"] in EXPECT_BLOCK),
            "vuln_total": sum(1 for r in mine if r["kind"] in EXPECT_BLOCK),
            "clean_passed": sum(not r["blocked"] for r in mine
                                if r["kind"] not in EXPECT_BLOCK),
            "clean_total": sum(1 for r in mine if r["kind"] not in EXPECT_BLOCK),
            "detection": {tid: sum(tid in r["tp"] for r in mine if r["scenario"]
                                   == truths[tid]["scenario"]) for tid in truths},
            "failed_runs": sum(1 for r in data["rows"] if r["config"] == config
                               and r.get("failed")),
            "known": sum(r.get("known", 0) for r in mine),
        }
        costs = [r for r in mine if r.get("cost_usd") is not None]
        if costs:
            out[config]["cost"] = {k: statistics.mean(r[k] or 0 for r in costs)
                                   for k in ("duration_s", "wall_s", "llm_calls", "tool_calls",
                                             "tokens_in", "tokens_out", "cost_usd")}
            out[config]["model"] = sorted({f"{r.get('provider')}/{r.get('model')}"
                                           for r in costs})
            out[config]["patches"] = {k: sum(r.get(k) or 0 for r in costs)
                                      for k in ("patches", "patches_validated",
                                                "patches_failed")}
    return out


def truths_of(data: dict, scenario_id: str) -> list[dict]:
    return data["truths"].get(scenario_id, [])


def _mean(values: list[float]) -> str:
    if not values:
        return "-"
    if len(values) == 1:
        return f"{values[0]:.2f}"
    return f"{statistics.mean(values):.2f} ± {statistics.pstdev(values):.2f}"


def render(summary: dict, data: dict) -> str:
    lines = ["# Kết quả benchmark", "",
             "Chấm theo spec gốc mục 5.3. Ô có ± là trung bình ± độ lệch chuẩn qua các lần chạy.",
             "", "## Độ chính xác (chặt: NEEDS_REVIEW tính là dương tính)", "",
             ("| Cấu hình | LLM | Lần chạy | TP | FP | FN | Precision | Recall | F1 | "
             "F1 (lỏng) |"), "|---|---|---|---|---|---|---|---|---|---|"]
    for config, s in summary.items():
        strict = [r for r in s["per_rep"] if r["view"] == "strict"]
        lenient = [r for r in s["per_rep"] if r["view"] == "lenient"]
        lines.append(
            f"| {config} | {', '.join(s.get('model', ['—']))} | {s['reps']} | "
            f"{_mean([r['tp'] for r in strict])} | {_mean([r['fp'] for r in strict])} | "
            f"{_mean([r['fn'] for r in strict])} | {_mean([r['precision'] for r in strict])} | "
            f"{_mean([r['recall'] for r in strict])} | {_mean([r['f1'] for r in strict])} | "
            f"{_mean([r['f1'] for r in lenient])} |")
    groups = sorted({g for s in summary.values() for g in s["recall_by_group"]})
    lines += ["", "## Recall theo nhóm lỗ hổng", ""]
    if groups:
        lines += ["| Cấu hình | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
    else:
        lines.append("(các kịch bản được chọn không có lỗ hổng nào)")
    for config, s in summary.items() if groups else ():
        cells = []
        for g in groups:
            value, n = s["recall_by_group"].get(g, (None, 0))
            cells.append("-" if value is None else f"{value:.2f} (n={n})")
        lines.append(f"| {config} | " + " | ".join(cells) + " |")
    lines += ["", ("Phát hiện DAST đã có trên bản gốc S00 (cùng route, cùng nhóm CWE) là vấn đề "
                   "có sẵn, không do PR gây ra: không tính TP hay FP, được đếm riêng ở bảng dưới."),
              "", ("`measured:sast_sca`: C1 bắt được; `measured:dast_only`: chỉ ZAP bắt được; "
              "`measured:neither`: không công cụ nào bắt được."), "",
              "## Quyết định của quality gate (cấp PR)", "",
              ("| Cấu hình | PR có lỗ hổng bị chặn | PR sạch / mồi nhử được qua | "
               "FP trên PR sạch (mỗi lần chạy) | Báo lại phát hiện DAST có sẵn | Lần chạy lỗi |"),
              "|---|---|---|---|---|---|"]
    for config, s in summary.items():
        lines.append(f"| {config} | {s['vuln_blocked']}/{s['vuln_total']} | "
                     f"{s['clean_passed']}/{s['clean_total']} | "
                     f"{', '.join(map(str, s['fp_on_clean']))} | {s['known']} | "
                     f"{s['failed_runs']} |")
    costly = {c: s for c, s in summary.items() if "cost" in s}
    if costly:
        lines += ["", "## Chi phí mỗi PR (trung bình)", "",
                  ("| Cấu hình | Thời gian agent (s) | Thời gian cả lượt (s) | Lượt gọi LLM | "
                  "Lượt gọi công cụ | Token vào | Token ra | Chi phí quy đổi (USD) |"),
                  "|---|---|---|---|---|---|---|---|"]
        for config, s in costly.items():
            c = s["cost"]
            lines.append(f"| {config} | {c['duration_s']:.1f} | {c['wall_s']:.1f} | "
                         f"{c['llm_calls']:.1f} | {c['tool_calls']:.1f} | {c['tokens_in']:.0f} "
                         f"| {c['tokens_out']:.0f} | {c['cost_usd']:.4f} |")
        lines += ["", "## Bản vá đề xuất (cho kết luận TP)", "",
                  "| Cấu hình | Bản vá | Kiểm chứng đạt | Kiểm chứng không đạt |",
                  "|---|---|---|---|"]
        for config, s in costly.items():
            p = s["patches"]
            lines.append(f"| {config} | {p['patches']} | {p['patches_validated']} | "
                         f"{p['patches_failed']} |")
    truths = [t for ts in data["truths"].values() for t in ts]
    if truths:
        lines += ["", "## Từng lỗ hổng: số lần được phát hiện", "",
                  "| Lỗ hổng | Nhóm | " + " | ".join(summary) + " |",
                  "|---|---|" + "---|" * len(summary)]
        for t in truths:
            cells = [f"{s['detection'].get(t['id'], 0)}/{s['reps']}" for s in summary.values()]
            lines.append(f"| {t['id']} {t['title']} | {t['category']} | " + " | ".join(cells)
                         + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scan", required=True, help="fetched scan run id")
    ap.add_argument("--select", default="test")
    ap.add_argument("--configs", default="C2,C3,C4,C5")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    scan = RESULTS / "scans" / args.scan
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    data = collect(scan, sc.select(args.select), configs, _load_gate())
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
