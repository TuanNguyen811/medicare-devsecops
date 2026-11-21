import importlib.util
import json
import sys
from pathlib import Path

import zap2sarif

FIX = Path(__file__).parent / "fixtures"
GATE = Path(__file__).resolve().parents[2] / "gate" / "gate.py"


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def sarif():
    reports = {"DOCTOR": load("zap-DOCTOR.json"), "PATIENT": load("zap-PATIENT.json")}
    return zap2sarif.convert(reports, load("routes.json"))


def results_by_uri(doc):
    return {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r
            for r in doc["runs"][0]["results"]}


def test_merges_roles_and_maps_route():
    sqli = [r for r in sarif()["runs"][0]["results"] if r["ruleId"] == "40018"]
    assert len(sqli) == 1
    (r,) = sqli
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "dast:GET /patients/{patient_id}")
    assert r["properties"]["roles"] == ["DOCTOR", "PATIENT"]
    assert r["properties"]["cwe"] == "CWE-89" and r["properties"]["param"] == "q"
    related = r["relatedLocations"][0]["physicalLocation"]
    assert related["artifactLocation"]["uri"] == "app/medicare/patient/router.py"
    assert related["region"]["startLine"] == 40


def test_severity_and_informational_dropped():
    doc = sarif()
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["40018"]["properties"]["security-severity"] == "8.0"
    assert rules["10038"]["properties"]["security-severity"] == "5.0"
    assert rules["10020"]["properties"]["security-severity"] == "2.0"
    assert "CWE-89" in rules["40018"]["properties"]["tags"]
    assert "10027" not in rules
    assert all(r["ruleId"] != "10027" for r in doc["runs"][0]["results"])


def test_unmatched_url_normalised():
    r = results_by_uri(sarif())["dast:GET /static/x/{id}"]
    assert "relatedLocations" not in r


def test_template_prefers_same_method():
    routes = load("routes.json")
    assert zap2sarif.template("/login", routes, "POST")[1]["function"] == "login"
    path, route = zap2sarif.template("/login", routes, "GET")
    assert path == "/login" and route is None


def test_finding_id_matches_gate(tmp_path):
    spec = importlib.util.spec_from_file_location("gate", GATE)
    gate = importlib.util.module_from_spec(spec)
    sys.modules["gate"] = gate  # dataclasses look the module up
    spec.loader.exec_module(gate)
    out = tmp_path / "zap.sarif"
    out.write_text(json.dumps(sarif()), encoding="utf-8")
    findings = {f.id: f for f in gate.load_sarif(out, "zap", None)}
    sqli = findings["zap:40018:dast:GET /patients/{patient_id}:0"]
    assert sqli.severity == "HIGH" and sqli.related == ("app/medicare/patient/router.py",)


def test_cli_ok_and_fails_on_broken_report(tmp_path):
    out = tmp_path / "zap.sarif"
    ok = zap2sarif.main(["--routes", str(FIX / "routes.json"), "--out", str(out),
                         f"DOCTOR={FIX / 'zap-DOCTOR.json'}"])
    assert ok == 0 and json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    for report in (bad, tmp_path / "missing.json"):
        target = tmp_path / f"never-{report.stem}.sarif"
        code = zap2sarif.main(["--routes", str(FIX / "routes.json"), "--out", str(target),
                               f"DOCTOR={FIX / 'zap-DOCTOR.json'}", f"NURSE={report}"])
        assert code == 1 and not target.exists()
