#!/usr/bin/env python
"""
Deployment diagnostics script for Railway.
Run this to check if all required environment variables are set.
"""

import os
import sys

def check_env():
    """Check all required environment variables."""
    required_vars = {
        'DJANGO_SETTINGS_MODULE': 'Should be: config.settings.production',
        'SECRET_KEY': 'Should be a long random string',
        'DEBUG': 'Should be: False',
        'ALLOWED_HOSTS': 'Should include Railway domain',
        'DATABASE_URL': 'Should be PostgreSQL connection string',
    }

    print("=" * 60)
    print("RAILWAY DEPLOYMENT DIAGNOSTICS")
    print("=" * 60)
    print()

    all_ok = True

    for var, description in required_vars.items():
        value = os.environ.get(var)
        if value:
            # Mask sensitive values
            if var in ['SECRET_KEY', 'DATABASE_URL']:
                display_value = value[:10] + '...' + value[-10:] if len(value) > 20 else '***'
            else:
                display_value = value
            print(f"{var:25s} = {display_value}")
            print(f"({description})")
        else:
            print(f"{var:25s} = NOT SET")
            print(f"({description})")
            all_ok = False
        print()

    print("=" * 60)

    # Check Python version
    print(f"Python version: {sys.version}")
    print()

    # Check if Django can import settings
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.production')
        import django
        django.setup()
        print("Django settings loaded successfully")

        from django.conf import settings
        print(f"Database engine: {settings.DATABASES['default']['ENGINE']}")
        print(f"Static files root: {settings.STATIC_ROOT}")
        print(f"Debug mode: {settings.DEBUG}")

    except Exception as e:
        print(f"Error loading Django settings: {e}")
        all_ok = False

    print("=" * 60)

    if all_ok:
        print("All checks passed!")
        return 0
    else:
        print("Some checks failed. See above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(check_env())
