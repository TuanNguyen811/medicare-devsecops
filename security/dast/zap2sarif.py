"""Merge the ZAP JSON reports of several roles into one SARIF file (spec 4.2).

    python3 zap2sarif.py --routes routes.json --out zap.sarif DOCTOR=zap-DOCTOR.json ...

- Tool name `zap` (the file name), ruleId = ZAP pluginId. Severity (High 8.0, Medium 5.0,
  Low 2.0) is written on every result as properties.security-severity, from the HIGHEST risk any
  role saw for that (plugin, method, route): one plugin can raise alerts of different risks, and
  the gate must never see a High as Medium. The rule carries the highest risk of the plugin.
  Informational alerts are dropped.
- Location: artifactLocation.uri = "dast:<METHOD> <path template>", percent-encoded (a valid
  URI for code scanning; gate and agent decode it, so finding ids read
  "zap:<plugin>:dast:GET /patients/{patient_id}:0"), no region. The template is
  the FastAPI route path matching the URL (routes.json from export_routes.py), else the path
  with all-digit segments replaced by {id}. Query strings are dropped.
- relatedLocations: the route handler's file and line, so the AI agent's anti-hallucination
  check can anchor an FP verdict on the code that serves the URL.
- One result per (pluginId, METHOD, template); properties.roles lists every role that saw it.

- --code-scanning-out: a second SARIF for GitHub code scanning only, which accepts file
  locations alone (it rejects the dast: scheme). There each result sits at its route handler
  (or app/medicare/main.py when no route matched) and the message names the route. The gate
  and the AI agent always read the primary file.

Standard library only: runs on the CI runner and inside the ZAP container.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

SEVERITY = {"3": "8.0", "2": "5.0", "1": "2.0"}  # ZAP riskcode → security-severity
LEVEL = {"3": "error", "2": "warning", "1": "note"}
EVIDENCE_CHARS = 200
FALLBACK_FILE = "app/medicare/main.py"  # where unmatched URLs are shown in code scanning


class ReportError(Exception):
    """A ZAP report could not be read: the DAST stage must fail, never pass as 'no findings'."""


def _pattern(route_path: str) -> re.Pattern:
    parts = re.split(r"(\{[^}]+\})", route_path)
    regex = "".join("[^/]+" if p.startswith("{") else re.escape(p) for p in parts if p)
    return re.compile(f"^{regex}/?$")


def template(path: str, routes: list[dict], method: str) -> tuple[str, dict | None]:
    """The route path template for a URL path, and the matching route (or None)."""
    path = path or "/"
    candidates = [r for r in routes if r.get("method") == method] + [
        r for r in routes if r.get("method") != method]
    for route in candidates:
        if _pattern(route["path"]).match(path):
            return route["path"], route if route.get("method") == method else None
    return "/".join("{id}" if seg.isdigit() else seg for seg in path.split("/")), None


def _alerts(report: dict) -> list[dict]:
    sites = report.get("site")
    if not isinstance(sites, list) or not sites:
        # A real scan always reports the site it scanned; an empty list is a broken report.
        raise ReportError("report has no 'site' entries")
    return [a for site in sites if isinstance(site, dict)
            for a in site.get("alerts") or [] if isinstance(a, dict)]


def convert(reports: dict[str, dict], routes: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    merged: dict[tuple[str, str, str], dict] = {}
    for role, report in sorted(reports.items()):
        for alert in _alerts(report):
            risk = str(alert.get("riskcode", "0"))
            if risk not in SEVERITY:
                continue  # informational
            plugin = str(alert.get("pluginid") or alert.get("alertRef") or "unknown")
            name = str(alert.get("name") or alert.get("alert") or plugin)
            cwe = str(alert.get("cweid") or "")
            tags = ["security"] + ([f"CWE-{int(cwe)}"] if cwe.isdigit() and int(cwe) > 0 else [])
            rule = rules.setdefault(plugin, {
                "id": plugin, "name": name, "shortDescription": {"text": name},
                "properties": {"security-severity": SEVERITY[risk], "tags": tags},
            })
            if float(SEVERITY[risk]) > float(rule["properties"]["security-severity"]):
                rule["properties"]["security-severity"] = SEVERITY[risk]
            for inst in alert.get("instances") or []:
                if not isinstance(inst, dict):
                    continue
                method = str(inst.get("method") or "GET").upper()
                tmpl, route = template(urlsplit(str(inst.get("uri") or "")).path, routes, method)
                key = (plugin, method, tmpl)
                entry = merged.get(key)
                if entry is None:
                    entry = merged[key] = {
                        "ruleId": plugin, "level": LEVEL[risk], "message": {"text": name},
                        "locations": [{"physicalLocation": {"artifactLocation": {
                            "uri": "dast:" + quote(f"{method} {tmpl}", safe="/")}}}],
                        "properties": {
                            "security-severity": SEVERITY[risk],
                            "roles": [], "cwe": f"CWE-{cwe}" if tags[1:] else None,
                            "param": str(inst.get("param") or ""),
                            "evidence": str(inst.get("evidence") or "")[:EVIDENCE_CHARS],
                            "confidence": str(alert.get("confidence") or ""),
                        },
                    }
                    if route and route.get("file"):
                        entry["relatedLocations"] = [{"physicalLocation": {
                            "artifactLocation": {"uri": route["file"]},
                            "region": {"startLine": int(route.get("line") or 1)}}}]
                props = entry["properties"]
                if float(SEVERITY[risk]) > float(props["security-severity"]):
                    props["security-severity"] = SEVERITY[risk]
                    entry["level"] = LEVEL[risk]
                if role not in entry["properties"]["roles"]:
                    entry["properties"]["roles"] = sorted([*entry["properties"]["roles"], role])
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "zap", "informationUri": "https://www.zaproxy.org/",
                                "rules": [rules[k] for k in sorted(rules)]}},
            "results": [merged[k] for k in sorted(merged)],
        }],
    }


def for_code_scanning(sarif: dict) -> dict:
    """Same results, but located at the route handler file (code scanning needs file URIs)."""
    doc = copy.deepcopy(sarif)
    for result in doc["runs"][0]["results"]:
        route = unquote(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        related = result.pop("relatedLocations", None)
        result["locations"] = related or [{"physicalLocation": {
            "artifactLocation": {"uri": FALLBACK_FILE}, "region": {"startLine": 1}}}]
        result["message"] = {"text": f"{result['message']['text']} ({route.removeprefix('dast:')})"}
    return doc


def _load(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"{path.name}: {type(exc).__name__}") from exc
    if not isinstance(doc, dict):
        raise ReportError(f"{path.name}: not a JSON object")
    _alerts(doc)
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--routes", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--code-scanning-out", help="extra SARIF with file locations for upload-sarif")
    p.add_argument("reports", nargs="+", help="ROLE=path/to/zap-ROLE.json")
    args = p.parse_args(argv)
    try:
        routes = json.loads(Path(args.routes).read_text(encoding="utf-8"))
        reports = {}
        for item in args.reports:
            role, sep, path = item.partition("=")
            if not sep or not role:
                raise ReportError(f"expected ROLE=path, got {item!r}")
            reports[role] = _load(Path(path))
        sarif = convert(reports, routes if isinstance(routes, list) else [])
    except (ReportError, OSError, ValueError) as exc:
        print(f"zap2sarif: {exc}", file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8",
                              newline="")
    if args.code_scanning_out:
        Path(args.code_scanning_out).write_text(
            json.dumps(for_code_scanning(sarif), indent=2, ensure_ascii=False), encoding="utf-8",
            newline="")
    results = sarif["runs"][0]["results"]
    print(f"zap2sarif: {len(results)} results from {len(reports)} roles", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
