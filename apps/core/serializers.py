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
        fields = ['id', 'username', 'email', 'profile', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class CurrentUserSerializer(serializers.ModelSerializer):
    """
    Serializer for current authenticated user.
    Includes additional fields useful for React state.
    """
    user_type = serializers.CharField(source='profile.user_type', read_only=True)
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

    def get_is_participant(self, obj):
        """Check if user is a participant."""
        return obj.profile.user_type == 'PARTICIPANT'

    def get_is_admin(self, obj):
        """Check if user is admin."""
        return obj.is_staff or obj.is_superuser