#!/usr/bin/env bash
# Railway deployment build script for C3DS monorepo
# This script builds both the React frontend and Django backend in a single deployment

set -e  # Exit immediately if any command fails

echo "Building C3DS for Railway..."

# =============================================================================
# FRONTEND BUILD
# =============================================================================

echo "Installing frontend dependencies..."
cd ../c3ds-frontend
npm install

echo "Building React app..."
npm run build
echo "React build complete - output in c3ds-frontend/dist/"

# =============================================================================
# BACKEND SETUP
# =============================================================================

echo "Installing Python dependencies..."
cd ../c3ds
pip install -r requirements.txt

echo "Collecting static files (includes React build)..."
python manage.py collectstatic --noinput
echo "Static files collected to staticfiles/"

echo "Running database migrations..."
python manage.py migrate --noinput
echo "Database migrations complete"

echo ""
echo "Build complete!"
echo "Ready to start with: gunicorn config.wsgi:application"
