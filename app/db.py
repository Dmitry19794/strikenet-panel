"""
SQLite-слой. Все операции синхронные (sqlite3 не async),
вызываются из asyncio через run_in_executor там, где нужно.
"""
import sqlite3
import json
import datetime
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent.parent / "orchestrator.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url   TEXT NOT NULL,
    target_repo  TEXT,
    tools        TEXT NOT NULL DEFAULT '[]',   -- JSON-список
    status       TEXT NOT NULL DEFAULT 'pending',
    progress     INTEGER NOT NULL DEFAULT 0,
    started_at   TEXT,
    finished_at  TEXT,
    llm_provider TEXT,
    llm_model    TEXT,
    nono_enabled INTEGER NOT NULL DEFAULT 1,
    reset_stages INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS stages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    tool            TEXT NOT NULL,
    order_index     INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    started_at      TEXT,
    finished_at     TEXT,
    raw_output_path TEXT,
    error           TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    stage_id    INTEGER NOT NULL REFERENCES stages(id),
    tool        TEXT NOT NULL,
    vuln_type   TEXT,
    endpoint    TEXT,
    parameter   TEXT,
    severity    TEXT,
    description TEXT,
    poc         TEXT,
    dedup_key   TEXT NOT NULL,
    confirmed_by TEXT NOT NULL DEFAULT '[]'  -- JSON-список инструментов
);

CREATE TABLE IF NOT EXISTS schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url  TEXT NOT NULL,
    target_repo TEXT,
    tools       TEXT NOT NULL DEFAULT '[]',
    cron        TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_run_at TEXT,
    next_run_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS llm_providers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    endpoint      TEXT NOT NULL,
    api_key       TEXT,
    default_model TEXT
);

-- дефолтные настройки
INSERT OR IGNORE INTO settings VALUES ('instance_name','StrikeNet Orchestrator');
INSERT OR IGNORE INTO settings VALUES ('timezone','Europe/Bucharest');
INSERT OR IGNORE INTO settings VALUES ('results_dir','./results');
INSERT OR IGNORE INTO settings VALUES ('reset_script','./reset-target.sh');
INSERT OR IGNORE INTO settings VALUES ('retention_days','90');
INSERT OR IGNORE INTO settings VALUES ('nono_enabled','1');
INSERT OR IGNORE INTO settings VALUES ('notify_critical','1');
INSERT OR IGNORE INTO settings VALUES ('notify_done','1');
INSERT OR IGNORE INTO settings VALUES ('notify_error','1');
-- LLM настройки
INSERT OR IGNORE INTO settings VALUES ('llm_provider_type','openrouter');
INSERT OR IGNORE INTO settings VALUES ('llm_api_key','');
INSERT OR IGNORE INTO settings VALUES ('llm_model','deepseek/deepseek-r1:free');
INSERT OR IGNORE INTO settings VALUES ('llm_custom_url','');
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def _now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds")


# ── RUNS ──
def create_run(target_url, target_repo, tools, llm_provider=None,
               llm_model=None, nono_enabled=True, reset_stages=True) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO runs
               (target_url, target_repo, tools, status, llm_provider, llm_model,
                nono_enabled, reset_stages)
               VALUES (?,?,?,?,?,?,?,?)""",
            (target_url, target_repo, json.dumps(tools), "pending",
             llm_provider, llm_model, int(nono_enabled), int(reset_stages)),
        )
        return cur.lastrowid


def update_run(run_id: int, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE runs SET {cols} WHERE id = ?",
                     list(fields.values()) + [run_id])


def get_run(run_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            return None
        r = dict(row)
        r["tools"] = json.loads(r["tools"])
        return r


def list_runs(status: str | None = None, limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        q = "SELECT * FROM runs"
        params = []
        if status:
            q += " WHERE status = ?"
            params.append(status)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
    result = []
    for row in rows:
        r = dict(row)
        r["tools"] = json.loads(r["tools"])
        result.append(r)
    return result


def get_run_stats() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM runs WHERE status='running'").fetchone()[0]
        paused = conn.execute("SELECT COUNT(*) FROM runs WHERE status='paused'").fetchone()[0]
        done = conn.execute("SELECT COUNT(*) FROM runs WHERE status='done'").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        hi = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE severity IN ('critical','high')"
        ).fetchone()[0]
        sev = {}
        for s in ("critical","high","medium","low","info"):
            sev[s] = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity=?", (s,)
            ).fetchone()[0]
    return dict(total=total, active=active, paused=paused, done=done,
                findings=findings, hi_findings=hi, severity=sev)


# ── STAGES ──
def create_stage(run_id: int, tool: str, order_index: int) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO stages (run_id, tool, order_index, status) VALUES (?,?,?,'pending')",
            (run_id, tool, order_index),
        )
        return cur.lastrowid


def update_stage(stage_id: int, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE stages SET {cols} WHERE id = ?",
                     list(fields.values()) + [stage_id])


def get_stages(run_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM stages WHERE run_id = ? ORDER BY order_index", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def delete_incomplete_stages(run_id: int):
    """Удаляет этапы прогона, не дошедшие до done/skipped (нужно для resume)."""
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM stages WHERE run_id = ? AND status NOT IN ('done','skipped')",
            (run_id,),
        )


# ── FINDINGS ──
def add_finding(run_id: int, stage_id: int, tool: str, finding: dict):
    dedup = f"{finding.get('vuln_type','')}|{finding.get('endpoint','')}|{finding.get('parameter','')}".lower()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id, confirmed_by FROM findings WHERE run_id=? AND dedup_key=?",
            (run_id, dedup),
        ).fetchone()
        if existing:
            cb = json.loads(existing["confirmed_by"])
            if tool not in cb:
                cb.append(tool)
            conn.execute(
                "UPDATE findings SET confirmed_by=? WHERE id=?",
                (json.dumps(cb), existing["id"]),
            )
        else:
            conn.execute(
                """INSERT INTO findings
                   (run_id,stage_id,tool,vuln_type,endpoint,parameter,
                    severity,description,poc,dedup_key,confirmed_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (run_id, stage_id, tool,
                 finding.get("vuln_type"), finding.get("endpoint"),
                 finding.get("parameter"), finding.get("severity"),
                 finding.get("description"), finding.get("poc"),
                 dedup, json.dumps([tool])),
            )


def get_findings(run_id: int | None = None, severity: str | None = None,
                 tool: str | None = None) -> list[dict]:
    with get_conn() as conn:
        q = "SELECT * FROM findings WHERE 1=1"
        params = []
        if run_id:
            q += " AND run_id=?"; params.append(run_id)
        if severity:
            q += " AND severity=?"; params.append(severity)
        if tool:
            q += " AND tool=?"; params.append(tool)
        q += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        rows = conn.execute(q, params).fetchall()
    result = []
    for row in rows:
        r = dict(row)
        r["confirmed_by"] = json.loads(r["confirmed_by"])
        result.append(r)
    return result


# ── SCHEDULES ──
def create_schedule(target_url, target_repo, tools, cron, active=True) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO schedules (target_url,target_repo,tools,cron,active) VALUES (?,?,?,?,?)",
            (target_url, target_repo, json.dumps(tools), cron, int(active)),
        )
        return cur.lastrowid


def list_schedules() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()
    result = []
    for row in rows:
        r = dict(row)
        r["tools"] = json.loads(r["tools"])
        result.append(r)
    return result


def delete_schedule(sched_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM schedules WHERE id=?", (sched_id,))


# ── SETTINGS ──
def get_settings() -> dict:
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}


def save_settings(data: dict):
    with get_conn() as conn:
        for k, v in data.items():
            conn.execute(
                "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=?",
                (k, str(v), str(v)),
            )


# ── LLM PROVIDERS ──
def list_llm_providers() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM llm_providers").fetchall()
        return [dict(r) for r in rows]


def add_llm_provider(name, provider_type, endpoint, api_key=None, default_model=None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO llm_providers (name,provider_type,endpoint,api_key,default_model) VALUES (?,?,?,?,?)",
            (name, provider_type, endpoint, api_key, default_model),
        )
        return cur.lastrowid


def delete_llm_provider(provider_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM llm_providers WHERE id=?", (provider_id,))
