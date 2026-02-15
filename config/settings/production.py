"""
Production settings for C3DS Django backend.

This settings file is designed for Railway.app deployment with PostgreSQL.
All sensitive values are read from environment variables.
"""

from .base import *
from decouple import config, Csv
import dj_database_url
from pathlib import Path
import os

# Security
DEBUG = config('DEBUG', cast=bool, default=False)
SECRET_KEY = config('SECRET_KEY')
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

# Database - Railway PostgreSQL
# Railway automatically provides DATABASE_URL environment variable
# If not set, dj_database_url will raise an error (which is correct for production)
DATABASES = {
    'default': dj_database_url.config(
        conn_max_age=600,  # Connection pooling (10 minutes)
        conn_health_checks=True,  # Enable health checks
    )
}

# Static files (whitenoise)
# Collect static files to this directory for serving
STATIC_ROOT = BASE_DIR.parent / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# CORS - Production frontend domains
# Only allow requests from specified origins
# Default to empty list if not set (will need to be configured after frontend deployment)
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', cast=Csv, default='')
CSRF_TRUSTED_ORIGINS = [f"https://{host}" for host in ALLOWED_HOSTS]

# Security headers (enforce HTTPS)
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', cast=bool, default=True)
SESSION_COOKIE_SECURE = True  # Only send session cookie over HTTPS
CSRF_COOKIE_SECURE = True  # Only send CSRF cookie over HTTPS
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Certificate Authority files (Railway volume)
# CA files are mounted at /data/ca via Railway volume
CA_DIR = Path('/data/ca')
CA_CERTIFICATE_PATH = CA_DIR / 'ca_certificate.pem'
CA_PRIVATE_KEY_PATH = CA_DIR / 'ca_private_key.pem'

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': config('DJANGO_LOG_LEVEL', default='INFO'),
            'propagate': False,
        },
    },
}
