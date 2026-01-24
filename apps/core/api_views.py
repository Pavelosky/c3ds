"""
API views for authentication and user management.
File: apps/core/api_views.py

REST API endpoints for user authentication and profile data.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from django.contrib.auth import logout
from apps.core.serializers import CurrentUserSerializer


class CurrentUserView(APIView):
    """
    GET /api/v1/auth/me/

    Returns current authenticated user info.
    React calls this on app load to get user state.

    Requires authentication (uses Django session).

    Example response:
    {
        "id": 1,
        "username": "participant1",
        "email": "participant@example.com",
        "user_type": "PARTICIPANT",
        "is_participant": true,
        "is_admin": false,
        "date_joined": "2024-01-01T10:00:00Z"
    }

    If not authenticated, returns 401 Unauthorized.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Return current user data."""
        serializer = CurrentUserSerializer(request.user)
        return Response(serializer.data)
    

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    POST /api/v1/auth/logout/
    Logs out the current user by terminating the session.
    """
    logout(request)
    return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)