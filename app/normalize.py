"""
Парсеры вывода каждого инструмента → общая схема finding.
Перед первым боевым прогоном проверьте реальный JSON каждого инструмента:
    cat results/<run_id>/00-deepaudit.json | python3 -m json.tool | head -60
и поправьте ключи под то, что увидите.
"""
import json
from pathlib import Path


def _read_json(path: str) -> dict | list | None:
    try:
        text = Path(path).read_text()
        return json.loads(text)
    except Exception:
        return None


def normalize_deepaudit(raw_path: str) -> list[dict]:
    data = _read_json(raw_path)
    if not data:
        return []
    findings = []
    for item in (data.get("findings") or []):
        verified = item.get("verified", False)
        findings.append({
            "vuln_type": item.get("vulnerability_class", "unknown"),
            "endpoint": item.get("file_path", ""),
            "parameter": str(item.get("line_number", "")),
            "severity": (item.get("severity") or "info").lower(),
            "description": ("[PoC ✓] " if verified else "[не подтверждён] ")
                           + item.get("description", ""),
            "poc": item.get("poc_script", ""),
        })
    return findings


def normalize_hexstrike(raw_path: str) -> list[dict]:
    data = _read_json(raw_path)
    if not data:
        return []
    findings = []
    for item in (data.get("results") or []):
        findings.append({
            "vuln_type": item.get("vulnerability_type") or item.get("type", "unknown"),
            "endpoint": item.get("target") or item.get("url", ""),
            "parameter": item.get("parameter", ""),
            "severity": (item.get("severity") or "info").lower(),
            "description": item.get("description", ""),
            "poc": item.get("evidence") or item.get("output", ""),
        })
    return findings


def normalize_strix(raw_dir: str) -> list[dict]:
    out_dir = Path(raw_dir)
    report_file = next(out_dir.glob("**/*.json"), None)
    if not report_file:
        return []
    data = _read_json(str(report_file))
    if not data:
        return []
    findings = []
    for vuln in (data.get("vulnerabilities") or []):
        findings.append({
            "vuln_type": vuln.get("category", "unknown"),
            "endpoint": vuln.get("url", ""),
            "parameter": vuln.get("param", ""),
            "severity": (vuln.get("severity") or "info").lower(),
            "description": vuln.get("summary", ""),
            "poc": vuln.get("proof_of_concept", ""),
        })
    return findings


def normalize_shannon_sarif(sarif_path: str) -> list[dict]:
    data = _read_json(sarif_path)
    if not data:
        return []
    _level = {"error": "high", "warning": "medium", "note": "low"}
    findings = []
    for run in (data.get("runs") or []):
        for result in (run.get("results") or []):
            locs = result.get("locations") or []
            endpoint = ""
            if locs:
                phys = locs[0].get("physicalLocation", {})
                endpoint = phys.get("artifactLocation", {}).get("uri", "")
            findings.append({
                "vuln_type": result.get("ruleId", "unknown"),
                "endpoint": endpoint,
                "parameter": "",
                "severity": _level.get(result.get("level", "note"), "info"),
                "description": (result.get("message") or {}).get("text", ""),
                "poc": "",
            })
    return findings


NORMALIZERS = {
    "deepaudit": normalize_deepaudit,
    "hexstrike": normalize_hexstrike,
    "strix": normalize_strix,
    "shannon": normalize_shannon_sarif,
}
