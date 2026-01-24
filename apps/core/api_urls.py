"""
API URLs for authentication and user management.
"""

from django.urls import path
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse
from apps.core.api_views import CurrentUserView, logout_view

@ensure_csrf_cookie
def get_csrf_token(request):
    """
    Return CSRF token to React frontend.

    React will call this on app initialization to get the token,
    then include it in X-CSRFToken header for all changes.
    """
    return JsonResponse({'detail': 'CSRF cookie set'})

urlpatterns = [
    path('csrf/', get_csrf_token, name='api-csrf-token'),
    path('me/', CurrentUserView.as_view(), name='api-current-user'),
        path('logout/', logout_view, name='api_logout')
]