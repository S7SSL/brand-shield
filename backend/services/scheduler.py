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
        _scheduler.add_job(
        _run_auto_resolve,
        trigger=CronTrigger(hour=0, minute=0),
        id="brand_shield_auto_resolve",
        name="Brand Shield daily auto-resolve (midnight UTC)",
        replace_existing=True,
    )

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
            logger.warning(f"Weekly report not sent: {result.get('reason', result.get('error', 'unknown'))}")
    except Exception as e:
        logger.error(f"Weekly report failed: {e}", exc_info=True)


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

    # Weekly report job (every Monday at 8:00 AM UTC)
    _scheduler.add_job(
        _run_weekly_report,
        trigger=CronTrigger(day_of_week="mon", hour=8, minute=0),
        id="brand_shield_weekly_report",
        name="Brand Shield weekly report (Mon 8AM UTC)",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info(
        f"Scheduler started: scanning every {SCAN_INTERVAL_HOURS} hours, "
        f"weekly report every Monday 8AM UTC"
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




def _run_auto_resolve():
    """Auto-resolve threats older than 24 hours that haven't been actioned."""
    try:
        from datetime import datetime, timezone, timedelta
        from backend.database import query, execute

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        old_threats = query(
            "SELECT id FROM threats WHERE status = 'new' AND detected_at < ?",
            (cutoff,),
        )
        if old_threats:
            now = datetime.now(timezone.utc).isoformat()
            for t in old_threats:
                execute(
                    "UPDATE threats SET status = 'resolved', resolved_at = ? WHERE id = ?",
                    (now, t["id"]),
                )
            logger.info("[AUTO-RESOLVE] Resolved %d stale threats (older than 24h)", len(old_threats))
        else:
            logger.info("[AUTO-RESOLVE] No stale threats to resolve")
    except Exception as exc:
        logger.error("[AUTO-RESOLVE] Error: %s", exc)

def trigger_report_now():
    """Manually trigger a weekly report (called from API)."""
    _run_weekly_report()
