"""
APScheduler-интеграция.
При старте приложения восстанавливает все активные расписания из БД.
"""
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from . import db
from .pipeline import run_pipeline

scheduler = AsyncIOScheduler(timezone="UTC")


async def _fire_schedule(sched_id: int, target_url: str,
                         target_repo: str, tools: list):
    run_id = db.create_run(
        target_url=target_url,
        target_repo=target_repo,
        tools=tools,
        llm_provider=None,
    )
    asyncio.create_task(
        run_pipeline(run_id, target_url, target_repo or "", tools,
                     nono_enabled=True, reset_between=True, llm_provider=None)
    )


def register_schedule(sched: dict):
    parts = sched["cron"].split()
    if len(parts) != 5:
        return
    minute, hour, day, month, dow = parts
    scheduler.add_job(
        _fire_schedule,
        CronTrigger(minute=minute, hour=hour, day=day,
                    month=month, day_of_week=dow, timezone="UTC"),
        id=f"sched_{sched['id']}",
        replace_existing=True,
        kwargs=dict(
            sched_id=sched["id"],
            target_url=sched["target_url"],
            target_repo=sched.get("target_repo") or "",
            tools=sched["tools"],
        ),
    )


def unregister_schedule(sched_id: int):
    job_id = f"sched_{sched_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def init_scheduler():
    """Восстанавливает расписания из БД и запускает планировщик."""
    for sched in db.list_schedules():
        if sched["active"]:
            try:
                register_schedule(sched)
            except Exception as e:
                print(f"[scheduler] не удалось восстановить #{sched['id']}: {e}")
    scheduler.start()
