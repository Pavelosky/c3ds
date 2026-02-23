"""
Celery tasks for scheduled anomaly analysis.

The single entry-point task `run_anomaly_analysis` calls all detection
functions in sequence. Failures in one check do not abort the others.

Scheduled via CELERY_BEAT_SCHEDULE in settings (every 5 minutes by default).
"""
from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, name='apps.anomaly_detection.tasks.run_anomaly_analysis')
def run_anomaly_analysis(self):
    """
    Run all scheduled anomaly detection checks.

    Each check is called independently so a failure in one does not prevent
    the others from running. Errors are logged but not re-raised — Celery
    Beat will retry on the next scheduled interval.
    """
    from .detection import check_detection_rate_spike, check_silent_devices

    checks = [
        ('detection_rate_spike', check_detection_rate_spike),
        ('silent_devices', check_silent_devices),
    ]

    results = {}
    for name, fn in checks:
        try:
            fn()
            results[name] = 'ok'
            logger.info("Anomaly check '%s' completed successfully.", name)
        except Exception as exc:
            results[name] = f'error: {exc}'
            logger.error("Anomaly check '%s' failed: %s", name, exc, exc_info=True)

    return results
