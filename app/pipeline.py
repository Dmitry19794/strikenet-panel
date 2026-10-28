"""
Pipeline движок.
Каждый этап запускается СТРОГО после предыдущего.
После мутирующих этапов (Strix, Shannon) вызывается reset-target.sh.
Каждая строка лога отправляется в WebSocket через ws_manager.emit_log().
"""
import asyncio
import datetime
import os
from pathlib import Path

from . import db
from .normalize import NORMALIZERS
from .ws_manager import ws_manager
from .llm_config import build_env_for_tool, merge_with_os_env, get_active_provider

RESULTS_ROOT = Path(__file__).parent.parent / "results"
RESET_SCRIPT = Path(__file__).parent.parent / "reset-target.sh"
NONO_PROFILES_DIR = Path(__file__).parent.parent / "nono_profiles"


# ── инструменты в правильном порядке ──
TOOL_ORDER = ["deepaudit", "hexstrike", "strix", "shannon"]

# ── флаги: нужен ли сброс цели после инструмента ──
NEEDS_RESET = {"strix": True, "shannon": True}

# ── нужен ли target_repo для инструмента ──
NEEDS_REPO = {"deepaudit", "shannon"}


def _now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds")


def _build_cmd(tool: str, target_url: str, target_repo: str,
               out_path: str, nono: bool, results_dir: str) -> list[str]:
    """Собирает команду запуска с опциональной nono-обёрткой."""
    nono_profile = Path(results_dir) / "nono_resolved" / f"{tool}.json"

    def wrap(cmd: list[str]) -> list[str]:
        if nono and nono_profile.exists():
            return ["nono", "run", "--profile-file", str(nono_profile), "--"] + cmd
        return cmd

    if tool == "deepaudit":
        return wrap([
            "docker", "run", "--rm",
            "-v", f"{target_repo}:/workspace:ro",
            "-v", f"{out_path}:/results",
            "deepaudit:latest",
            "scan", "--project", "/workspace", "--output", "/results/00-deepaudit.json",
        ])
    if tool == "hexstrike":
        return wrap([
            "docker", "exec", "hexstrike",
            "curl", "-s", "-X", "POST", "http://localhost:8888/api/scan",
            "-H", "Content-Type: application/json",
            "-d", f'{{"target":"{target_url}","mode":"recon-only"}}',
        ])
    if tool == "strix":
        return wrap([
            "docker", "exec", "strix-cli",
            "strix", "--target", target_url,
            "--output", out_path,
        ])
    if tool == "shannon":
        cmd = ["npx", "@keygraph/shannon@latest", "start",
               "-u", target_url, "--output-dir", out_path]
        if target_repo:
            cmd += ["-r", target_repo]
        return wrap(cmd)
    return []


def _resolve_nono_profiles(target_url: str, target_repo: str,
                            results_dir: str, llm_host: str):
    """Подставляет реальные пути в шаблоны nono_profiles/*.json."""
    import json, re
    resolved_dir = Path(results_dir) / "nono_resolved"
    resolved_dir.mkdir(parents=True, exist_ok=True)
    ctx = {
        "TARGET_REPO": target_repo or "",
        "RESULTS_DIR": results_dir,
        "TARGET_HOST": re.sub(r"^https?://", "", target_url).split("/")[0],
        "LLM_PROVIDER_HOST": llm_host,
    }
    for p in NONO_PROFILES_DIR.glob("*.json"):
        raw = p.read_text()
        for k, v in ctx.items():
            raw = raw.replace(f"${{{k}}}", v)
        raw = re.sub(r"\$\{[A-Z_]+\}", "", raw)
        (resolved_dir / p.name).write_text(raw)


async def _log(run_id: int, level: str, tool: str, msg: str):
    import datetime as dt
    line = {
        "t": dt.datetime.now().strftime("%H:%M:%S"),
        "lvl": level,
        "tool": tool.upper(),
        "msg": msg,
    }
    await ws_manager.emit_log(run_id, line)


async def _run_cmd(cmd: list[str], run_id: int, tool: str,
                   out_file: str | None = None,
                   env: dict | None = None) -> tuple[bool, str]:
    """Запускает subprocess, стримит stdout в лог WebSocket."""
    await _log(run_id, "info", tool, "$ " + " ".join(cmd[:6]) + (" ..." if len(cmd) > 6 else ""))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,   # None → наследует os.environ полностью
        )
        stdout, stderr = await proc.communicate()

        # если инструмент пишет в stdout (например HexStrike через curl)
        if out_file and stdout:
            Path(out_file).parent.mkdir(parents=True, exist_ok=True)
            Path(out_file).write_bytes(stdout)

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[:500]
            await _log(run_id, "error", tool, f"exit {proc.returncode}: {err}")
            return False, err
        await _log(run_id, "ok", tool, "Этап завершён успешно")
        return True, ""
    except FileNotFoundError as e:
        await _log(run_id, "error", tool, f"Команда не найдена: {e}")
        return False, str(e)
    except Exception as e:
        await _log(run_id, "error", tool, str(e))
        return False, str(e)


async def _reset_target(run_id: int):
    await _log(run_id, "info", "ORCH", "Сброс состояния цели → reset-target.sh")
    if RESET_SCRIPT.exists():
        proc = await asyncio.create_subprocess_exec(str(RESET_SCRIPT))
        await proc.wait()
    else:
        await _log(run_id, "info", "ORCH",
                   "reset-target.sh не найден — сброс пропущен")
    await asyncio.sleep(10)
    await _log(run_id, "ok", "ORCH", "Цель готова к следующему этапу")


async def run_pipeline(run_id: int, target_url: str, target_repo: str,
                       tools: list[str], nono_enabled: bool,
                       reset_between: bool, llm_provider: str | None):
    """Главная функция пайплайна — вызывается как asyncio.create_task()."""
    db.update_run(run_id, status="running", started_at=_now(), progress=0)

    results_dir = str(RESULTS_ROOT / str(run_id))
    Path(results_dir).mkdir(parents=True, exist_ok=True)

    await _log(run_id, "info", "ORCH",
               f"Прогон #{run_id} запущен → {target_url}")
    await _log(run_id, "info", "ORCH",
               f"Инструменты: {', '.join(tools)} | nono: {nono_enabled}")

    # ── получаем активный LLM-провайдер и логируем (без ключа) ──
    provider = get_active_provider()
    if provider:
        await _log(run_id, "info", "ORCH",
                   f"LLM: {provider['provider_type']} | "
                   f"endpoint: {provider['base_url']} | "
                   f"model: {provider['model']}")
    else:
        await _log(run_id, "warn", "ORCH",
                   "LLM-провайдер не настроен — инструменты могут упасть")

    # nono-профили
    if nono_enabled:
        llm_host = "openrouter.ai"
        if llm_provider and "ollama" in llm_provider.lower():
            llm_host = "localhost:11434"
        _resolve_nono_profiles(target_url, target_repo or "", results_dir, llm_host)
        await _log(run_id, "info", "ORCH", "nono-профили сгенерированы")

    # отбираем и сортируем выбранные инструменты в правильном порядке
    ordered = [t for t in TOOL_ORDER if t in tools]
    total = len(ordered)

    try:
        for idx, tool in enumerate(ordered):
            # пропускаем DeepAudit если нет репозитория
            if tool in NEEDS_REPO and not target_repo:
                await _log(run_id, "info", "ORCH",
                           f"Пропуск {tool} — путь к репозиторию не указан")
                stage_id = db.create_stage(run_id, tool, idx)
                db.update_stage(stage_id, status="skipped")
                continue

            stage_id = db.create_stage(run_id, tool, idx)
            db.update_stage(stage_id, status="running", started_at=_now())
            await _log(run_id, "info", "ORCH",
                       f"═══ Этап {idx+1}/{total}: {tool.upper()} ═══")

            # путь к выводу
            out_path = f"{results_dir}/{idx:02d}-{tool}"
            if tool == "hexstrike":
                out_file = out_path + ".json"
            elif tool == "deepaudit":
                out_file = out_path + "/00-deepaudit.json"
            elif tool == "shannon":
                out_file = out_path + "/report.sarif"
            else:
                out_file = None

            cmd = _build_cmd(tool, target_url, target_repo or "",
                             out_path, nono_enabled, results_dir)
            if not cmd:
                await _log(run_id, "error", "ORCH", f"Неизвестный инструмент: {tool}")
                continue

            # ── строим env для этого конкретного инструмента ──
            tool_env_vars = build_env_for_tool(tool, provider)
            full_env = merge_with_os_env(tool_env_vars)
            await _log(run_id, "info", tool,
                       f"LLM env: BASE_URL={tool_env_vars.get('OPENAI_BASE_URL','')} "
                       f"MODEL={tool_env_vars.get('OPENAI_MODEL','')} "
                       f"KEY={'***' if tool_env_vars.get('OPENAI_API_KEY') else 'не задан'}")

            ok, err = await _run_cmd(cmd, run_id, tool, out_file, env=full_env)

            if not ok:
                db.update_stage(stage_id, status="failed",
                                finished_at=_now(), error=err[:500])
                db.update_run(run_id, status="failed", finished_at=_now())
                await _log(run_id, "error", "ORCH",
                           f"Этап {tool} провалился — пайплайн остановлен")
                await ws_manager.broadcast_runs({"type": "run_update",
                                                  "run_id": run_id, "status": "failed"})
                return

            # нормализация находок
            norm_path = out_file or out_path
            normalizer = NORMALIZERS.get(tool)
            if normalizer:
                try:
                    findings = normalizer(norm_path)
                    for f in findings:
                        db.add_finding(run_id, stage_id, tool, f)
                    await _log(run_id, "ok", tool,
                               f"Нормализовано находок: {len(findings)}")
                except Exception as e:
                    await _log(run_id, "info", tool,
                               f"Нормализация: {e}")

            db.update_stage(stage_id, status="done",
                            finished_at=_now(), raw_output_path=norm_path)

            # прогресс
            progress = int((idx + 1) / total * 100)
            db.update_run(run_id, progress=progress)
            await ws_manager.broadcast_runs({
                "type": "run_update", "run_id": run_id,
                "status": "running", "progress": progress,
                "current_stage": tool,
            })

            # сброс между мутирующими этапами
            next_tool = ordered[idx + 1] if idx + 1 < total else None
            if reset_between and NEEDS_RESET.get(tool) and next_tool:
                await _reset_target(run_id)

        # завершение
        db.update_run(run_id, status="done", finished_at=_now(), progress=100)
        total_f = len(db.get_findings(run_id))
        await _log(run_id, "ok", "ORCH",
                   f"✓ Пайплайн #{run_id} завершён. Итого находок: {total_f}")
        await ws_manager.broadcast_runs({
            "type": "run_update", "run_id": run_id,
            "status": "done", "progress": 100,
        })

    except asyncio.CancelledError:
        db.update_run(run_id, status="paused", finished_at=_now())
        await _log(run_id, "info", "ORCH", f"Прогон #{run_id} приостановлен")
    except Exception as e:
        db.update_run(run_id, status="failed", finished_at=_now())
        await _log(run_id, "error", "ORCH", f"Неожиданная ошибка: {e}")
        raise
