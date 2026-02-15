#!/bin/bash
set -e

echo "============================================"
echo "C3DS Backend Startup Script"
echo "============================================"

# Print environment info (without sensitive values)
echo "Django Settings Module: $DJANGO_SETTINGS_MODULE"
echo "Debug Mode: $DEBUG"
echo "Allowed Hosts: $ALLOWED_HOSTS"
echo "Database URL: ${DATABASE_URL:0:20}..." # Only show first 20 chars

echo ""
echo "Step 1: Checking database connectivity..."
python << END
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.production')
import django
django.setup()
from django.db import connection
try:
    connection.ensure_connection()
    print("[OK] Database connection successful")
except Exception as e:
    print(f"[ERROR] Database connection failed: {e}")
    exit(1)
END

echo ""
echo "Step 2: Running database migrations..."
python manage.py migrate --noinput

echo ""
echo "Step 3: Collecting static files..."
python manage.py collectstatic --noinput --clear

echo ""
echo "Step 4: Starting Gunicorn..."
exec gunicorn config.wsgi \
    --bind 0.0.0.0:${PORT:-8000} \
    --workers 4 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
