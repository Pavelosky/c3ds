"""
API views for authentication and user management.
File: apps/core/api_views.py

REST API endpoints for user authentication and profile data.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from django.contrib.auth import logout
from apps.core.serializers import CurrentUserSerializer, LoginSerializer, RegisterSerializer
from django.contrib.auth import login
from apps.core.forms import UserLoginForm, UserRegistrationForm
from drf_spectacular.utils import extend_schema, OpenApiResponse

# Custom SessionAuthentication that doesn't enforce CSRF for login/register
# This is necessary because:
# 1. Login/register are the first points of contact - no prior session exists
# 2. CSRF tokens require a previous GET request to be set, but these are POST-only endpoints
# 3. Credentials (username/password) provide sufficient authentication for these endpoints
# Other authenticated endpoints still use standard SessionAuthentication with CSRF protection
class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # Skip CSRF check

    


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

@extend_schema(
    request=LoginSerializer,
    responses={
        200: CurrentUserSerializer,
        400: OpenApiResponse(description="Validation errors"),
    },
    description="Authenticate user with username/password and create session cookie."
)
@api_view(['POST'])
@authentication_classes([CsrfExemptSessionAuthentication])
@permission_classes([AllowAny])
def login_view(request):
    """
    POST /api/v1/auth/login/
    
    Authenticate user and create session.
    
    Request body:
    {
        "username": "participant1",
        "password": "password123",
        "remember_me": false
    }
    
    Success response (200):
    {
        "id": 1,
        "username": "participant1",
        "email": "participant@example.com",
        "user_type": "PARTICIPANT",
        "is_participant": true,
        "is_admin": false,
        "date_joined": "2024-01-01T10:00:00Z"
    }
    """

    # Reuse existing form for validation
    form = UserLoginForm(data=request.data)

    if form.is_valid():
        user = form.get_user()
        login(request, user)

        # Session expiry matches template view behavior for consistency
        if not request.data.get('remember_me', False):
            request.session.set_expiry(0)  # Expires on browser close
        else:
            request.session.set_expiry(1209600)  # 2 weeks

        serializer = CurrentUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    else:
        # Wrap errors in 'errors' key so React can distinguish from other response types
        return Response({
            'errors': form.errors
        }, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    request=RegisterSerializer,
    responses={
        201: CurrentUserSerializer,
        400: OpenApiResponse(description="Validation errors"),
    },
    description="Register new user and create session. Auto-login after successful registration."
)
@api_view(['POST'])
@authentication_classes([CsrfExemptSessionAuthentication])
@permission_classes([AllowAny])
def register_view(request):
    """
    POST /api/v1/auth/register/

    Register new user and auto-login.

    Request body:
    {
        "username": "newuser",
        "email": "user@example.com",
        "password1": "securepassword123",
        "password2": "securepassword123",
        "user_type": "PARTICIPANT" or "NON_PARTICIPANT"
    }

    Success response (201):
    {
        "id": 2,
        "username": "newuser",
        "email": "user@example.com",
        "user_type": "PARTICIPANT",
        "is_participant": true,
        "is_admin": false,
        "date_joined": "2024-01-01T10:00:00Z"
    }
    """

    # Reuse existing form for validation and user creation
    form = UserRegistrationForm(data=request.data)

    if form.is_valid():
        user = form.save()

        # Set user type from form (profile created automatically via signal)
        user.profile.user_type = form.cleaned_data['user_type']
        user.profile.save()

        # Auto-login after registration (matches template behavior)
        login(request, user)

        serializer = CurrentUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    else:
        # Wrap errors in 'errors' key for consistent error handling in React
        return Response({
            'errors': form.errors
        }, status=status.HTTP_400_BAD_REQUEST)