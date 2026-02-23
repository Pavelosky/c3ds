"""
Celery application configuration for C3DS.

Workers handle background anomaly analysis tasks scheduled by Celery Beat.
In development, run these two processes alongside the Django dev server:

    celery -A config worker -l info
    celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

Reference:
- Celery 5.x docs: https://docs.celeryq.dev/en/stable/django/first-steps-with-django.html
- django-celery-beat: https://django-celery-beat.readthedocs.io/
"""
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

app = Celery('c3ds')

# Read config from Django settings, namespace all Celery keys with CELERY_
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in all installed apps (looks for tasks.py in each app)
app.autodiscover_tasks()
