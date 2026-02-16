"""
Production settings for C3DS project.

This module contains production-specific settings for Railway deployment.
Inherits from base settings and overrides with production values.
"""

from .base import *
import os

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

DEBUG = False

SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE-THIS-IN-PRODUCTION-PLEASE')

ALLOWED_HOSTS = [
    os.environ.get('RAILWAY_PUBLIC_DOMAIN', 'localhost'),
]

# trust X-Forwarded-Proto header
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Force HTTPS in production
SECURE_SSL_REDIRECT = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# =============================================================================
# SESSION & COOKIE SETTINGS
# =============================================================================

SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # JavaScript can't access session cookie
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection

# =============================================================================
# CSRF SETTINGS
# =============================================================================

CSRF_COOKIE_SECURE = True  # HTTPS only
CSRF_COOKIE_HTTPONLY = False  # MUST be False - React reads csrftoken via document.cookie
CSRF_COOKIE_SAMESITE = 'Lax'  # Prevent CSRF while allowing top-level navigation

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# Railway provides DATABASE_URL environment variable for PostgreSQL
import dj_database_url

DATABASES = {
    'default': dj_database_url.config(
        default=os.environ.get('DATABASE_URL'),
        conn_max_age=600,  # Connection pooling (10 minutes)
        conn_health_checks=True,  # Check connection health before reusing
    )
}

# =============================================================================
# STATIC FILES (WhiteNoise)
# =============================================================================

STATIC_ROOT = BASE_DIR / "staticfiles"

# WhiteNoise - efficient static file serving
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# WhiteNoise configuration for SPA
WHITENOISE_ROOT = BASE_DIR.parent / 'c3ds-frontend' / 'dist'  # Serve root files (index.html)
WHITENOISE_INDEX_FILE = True  # Enable SPA routing - serve index.html for directory requests

# =============================================================================
# CORS CONFIGURATION
# =============================================================================

# Same origin deployment - no CORS needed
CORS_ALLOWED_ORIGINS = []

# =============================================================================
# REST FRAMEWORK
# =============================================================================

# Remove BrowsableAPIRenderer in production (security best practice)
REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES'] = [
    'rest_framework.renderers.JSONRenderer',
]
