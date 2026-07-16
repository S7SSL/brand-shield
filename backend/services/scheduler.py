"""
Auto-scheduler for Brand Shield scans and weekly reports.
Runs periodic scans using APScheduler.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

_scheduler = None
_is_enabled = True


def _run_scheduled_scan():
    """Callback for scheduled scan execution."""
    if not _is_enabled:
        logger.info("Scheduled scan skipped (disabled)")
        return

    logger.info("Scheduled scan starting...")
    try:
        from backend.services.scanner import run_full_scan
        result = run_full_scan()
        logger.info(
            f"Scheduled scan complete: "
            f"{result['items_scanned']} items, {result['threats_found']} threats"
        )
    except Exception as e:
        logger.error(f"Scheduled scan failed: {e}", exc_info=True)


def _run_weekly_report():
    """Callback for weekly report email."""
    logger.info("Weekly report starting...")
    try:
        from backend.services.reporter import send_weekly_report
        result = send_weekly_report()
        if result.get("sent"):
            logger.info(f"Weekly report sent to {result.get('recipients')}")
        else:
            logger.warning(
                f"Weekly report not sent: {result.get('reason', result.get('error', 'unknown'))}"
            )
    except Exception as e:
        logger.error(f"Weekly report failed: {e}", exc_info=True)


def _run_daily_report():
    """Callback for the daily digest email."""
    logger.info("Daily digest starting...")
    try:
        from backend.services.reporter import send_daily_report
        result = send_daily_report()
        if result.get("sent"):
            logger.info(f"Daily digest sent to {result.get('recipients')}")
        else:
            logger.warning(
                f"Daily digest not sent: {result.get('reason', result.get('error', 'unknown'))}"
            )
    except Exception as e:
        logger.error(f"Daily digest failed: {e}", exc_info=True)


def _run_auto_resolve():
    """
    Housekeeping for stale threats.

    IMPORTANT: this used to mark ANY un-actioned threat older than 24h as
    'resolved', which silently discarded real threats before anyone saw them
    (a takedown pipeline that deletes its own queue is not end-to-end).
    Now: only LOW-severity, low-confidence threats are auto-ignored after
    7 days. Critical/high threats are never touched automatically.
    """
    try:
        from datetime import datetime, timezone, timedelta
        from backend.database import query, execute

        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        old_threats = query(
            """SELECT id FROM threats
               WHERE status = 'new' AND detected_at < ?
                 AND severity = 'low' AND confidence < 0.5""",
            (cutoff,),
        )
        for t in old_threats:
            execute("UPDATE threats SET status = 'ignored' WHERE id = ?", (t["id"],))
        if old_threats:
            logger.info(
                "[AUTO-IGNORE] Ignored %d stale low-severity threats (>7 days)",
                len(old_threats),
            )
    except Exception as exc:
        logger.error("[AUTO-IGNORE] Error: %s", exc)


def _run_monday_approval_reminder():
    """Callback for the weekly one-click approval email (Monday mornings).
    Skipped automatically when the pending queue is empty."""
    try:
        from backend.services.takedown import send_monday_approval_reminder
        result = send_monday_approval_reminder()
        logger.info(f"Monday approval reminder: {result}")
    except Exception as e:
        logger.error(f"Monday approval reminder failed: {e}", exc_info=True)


def _run_takedown_followups():
    """Check sent notices against their legal deadlines; follow up / escalate."""
    try:
        from backend.services.takedown import check_deadlines_and_followup
        result = check_deadlines_and_followup()
        if result.get("followups_sent") or result.get("marked_overdue"):
            logger.info(f"Takedown deadline check: {result}")
    except Exception as e:
        logger.error(f"Takedown deadline check failed: {e}", exc_info=True)


def init_scheduler(app=None):
    """
    Initialize and start the background scheduler.
    Call this when the Flask app starts.
    """
    global _scheduler

    if _scheduler is not None:
        logger.warning("Scheduler already initialized")
        return

    try:
        from backend.config import SCAN_INTERVAL_HOURS
    except ImportError:
        SCAN_INTERVAL_HOURS = 6

    _scheduler = BackgroundScheduler(daemon=True)

    # Auto-scan job (every N hours)
    _scheduler.add_job(
        _run_scheduled_scan,
        trigger=IntervalTrigger(hours=SCAN_INTERVAL_HOURS),
        id="brand_shield_scan",
        name=f"Brand Shield scan (every {SCAN_INTERVAL_HOURS}h)",
        replace_existing=True,
    )

    # Daily digest job (every day at 8:00 AM UTC) — emailed to REPORT_RECIPIENTS
    # (default sat@byerim.com only). Override time with REPORT_HOUR_UTC.
    import os as _os
    try:
        _report_hour = int(_os.getenv("REPORT_HOUR_UTC", "8"))
    except ValueError:
        _report_hour = 8
    _scheduler.add_job(
        _run_daily_report,
        trigger=CronTrigger(hour=_report_hour, minute=5),
        id="brand_shield_daily_report",
        name=f"BrandShield daily digest ({_report_hour}:05 UTC)",
        replace_existing=True,
    )

    # Daily auto-resolve job (midnight UTC)
    _scheduler.add_job(
        _run_auto_resolve,
        trigger=CronTrigger(hour=0, minute=0),
        id="brand_shield_auto_resolve",
        name="Brand Shield daily auto-resolve (midnight UTC)",
        replace_existing=True,
    )

    # Takedown deadline / follow-up job (hourly) — enforces the 48h NCII
    # and 72h DMCA clocks on sent notices.
    _scheduler.add_job(
        _run_takedown_followups,
        trigger=IntervalTrigger(hours=1),
        id="brand_shield_takedown_followups",
        name="Takedown deadline check (hourly)",
        replace_existing=True,
    )

    # Weekly one-click approval reminder (Mondays 8:00 UTC) — lists queued
    # draft notices with an Approve link. Skipped when the queue is empty.
    _scheduler.add_job(
        _run_monday_approval_reminder,
        trigger=CronTrigger(day_of_week="mon", hour=_report_hour, minute=0),
        id="brand_shield_monday_approval",
        name=f"Weekly approval reminder (Mon {_report_hour}:00 UTC)",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info(
        f"Scheduler started: scanning every {SCAN_INTERVAL_HOURS} hours, "
        f"daily digest {_report_hour}:05 UTC, "
        f"Monday approval reminder {_report_hour}:00 UTC, "
        f"stale-threat housekeeping midnight UTC, "
        f"takedown deadline check hourly"
    )


def stop_scheduler():
    """Shut down the scheduler."""
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler stopped")


def enable_scanning():
    """Enable scheduled scans."""
    global _is_enabled
    _is_enabled = True
    logger.info("Scheduled scanning enabled")


def disable_scanning():
    """Disable scheduled scans (scheduler keeps running but skips scans)."""
    global _is_enabled
    _is_enabled = False
    logger.info("Scheduled scanning disabled")


def get_status():
    """Return scheduler status info."""
    return {
        "scheduler_running": _scheduler is not None and _scheduler.running,
        "scanning_enabled": _is_enabled,
        "jobs": [
            {
                "id": job.id,
                "name": job.name,
                "next_run": str(job.next_run_time) if job.next_run_time else None,
            }
            for job in (_scheduler.get_jobs() if _scheduler else [])
        ],
    }


def trigger_report_now():
    """Manually trigger a weekly report (called from API)."""
    _run_weekly_report()
