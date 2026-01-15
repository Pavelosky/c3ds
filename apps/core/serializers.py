"""
Serializers for user authentication and profiles.
File: apps/core/serializers.py

Reference: DRF Serializers - https://www.django-rest-framework.org/api-guide/serializers/
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from apps.core.models import UserProfile

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for UserProfile model.
    Returns user type (ADMIN, PARTICIPANT, NON_PARTICIPANT).
    """
    class Meta:
        model = UserProfile
        fields = ['user_type']

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model with nested profile.
    Used for current user info and user lists.
    """
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ['username', 'profile', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class CurrentUserSerializer(serializers.ModelSerializer):
    """
    Serializer for current authenticated user.
    Includes additional fields useful for React state.
    """
    user_type = serializers.SerializerMethodField()
    is_participant = serializers.SerializerMethodField()
    is_admin = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'user_type',
            'is_participant',
            'is_admin',
            'date_joined',
        ]

        read_only_fields = ['id', 'date_joined']

    def get_user_type(self, obj):
        """Get user type, handling missing profile."""
        # Admin users might not have a profile
        if obj.is_staff or obj.is_superuser:
            return 'ADMIN'
        
        # Check if profile exists
        if hasattr(obj, 'profile'):
            return obj.profile.user_type
        
        # Default for users without profile
        return 'NON_PARTICIPANT'

    def get_is_participant(self, obj):
        """Check if user is a participant."""
        if not hasattr(obj, 'profile'):
            return False
        return obj.profile.user_type == 'PARTICIPANT'

    def get_is_admin(self, obj):
        """Check if user is admin."""
        return obj.is_staff or obj.is_superuser