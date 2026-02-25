"""
Auto-scheduler for Brand Shield scans.
Runs periodic scans using APScheduler.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

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
    _scheduler.add_job(
        _run_scheduled_scan,
        trigger=IntervalTrigger(hours=SCAN_INTERVAL_HOURS),
        id="brand_shield_scan",
        name=f"Brand Shield scan (every {SCAN_INTERVAL_HOURS}h)",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(f"Scheduler started: scanning every {SCAN_INTERVAL_HOURS} hours")


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
