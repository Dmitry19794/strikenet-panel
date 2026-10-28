"""
Генератор отчётов: SARIF 2.1.0, JSON, CSV.
PDF-экспорт отмечен как TODO — требует weasyprint или puppeteer.
"""
import json
import csv
import io
import datetime

from . import db


def _findings_for_run(run_id: int) -> list[dict]:
    return db.get_findings(run_id=run_id)


def generate_sarif(run_id: int) -> str:
    run = db.get_run(run_id)
    findings = _findings_for_run(run_id)
    _level = {"critical": "error", "high": "error",
              "medium": "warning", "low": "note", "info": "note"}
    results = []
    for f in findings:
        results.append({
            "ruleId": f["vuln_type"] or "unknown",
            "level": _level.get(f["severity"], "note"),
            "message": {"text": f["description"] or ""},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["endpoint"] or ""},
            }}],
            "properties": {
                "severity": f["severity"],
                "parameter": f["parameter"],
                "confirmed_by": f["confirmed_by"],
                "poc": bool(f["poc"]),
            },
        })
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "StrikeNet Orchestrator", "version": "0.9.1",
                                "informationUri": "https://github.com/your/repo"}},
            "results": results,
            "properties": {
                "run_id": run_id,
                "target": run["target_url"] if run else "",
                "generated_at": datetime.datetime.utcnow().isoformat(),
            },
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


def generate_json(run_id: int) -> str:
    run = db.get_run(run_id)
    findings = _findings_for_run(run_id)
    stages = db.get_stages(run_id)
    report = {
        "meta": {
            "run_id": run_id,
            "target": run["target_url"] if run else "",
            "tools": run["tools"] if run else [],
            "status": run["status"] if run else "",
            "started_at": run["started_at"] if run else "",
            "finished_at": run["finished_at"] if run else "",
            "generated_at": datetime.datetime.utcnow().isoformat(),
        },
        "stages": stages,
        "findings": findings,
        "summary": {
            s: len([f for f in findings if f["severity"] == s])
            for s in ("critical", "high", "medium", "low", "info")
        },
    }
    return json.dumps(report, ensure_ascii=False, indent=2)


def generate_csv(run_id: int) -> str:
    findings = _findings_for_run(run_id)
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=[
        "severity", "vuln_type", "endpoint", "parameter",
        "description", "poc", "confirmed_by", "tool",
    ])
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "severity": f["severity"],
            "vuln_type": f["vuln_type"],
            "endpoint": f["endpoint"],
            "parameter": f["parameter"],
            "description": (f["description"] or "")[:200],
            "poc": "да" if f["poc"] else "нет",
            "confirmed_by": ", ".join(f["confirmed_by"]),
            "tool": f["tool"],
        })
    return out.getvalue()
