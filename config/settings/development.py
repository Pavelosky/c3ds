from .base import *
from decouple import config

# Debug should be True for development
DEBUG = True

# Development secret key (not secure, only for local development)
SECRET_KEY = "django-insecure-dev-only-idwik1jp_i1ssn=16(*=y259un803qg-7r17)ma@u0_z1a!y!^"

# For development, we'll use SQLite
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Allow all hosts for development
ALLOWED_HOSTS = ['localhost', '127.0.0.1','192.168.1.100','192.168.1.*', '192.168.1.102']

# Development-specific installed apps (we'll add debug toolbar later)
INSTALLED_APPS += [
    # We'll add development-specific apps here later
]

# CSRF trusted origins for Vite dev server
CSRF_TRUSTED_ORIGINS = ['http://localhost:5173', 'http://127.0.0.1:5173']