"""
API URLs for dashboard.
File: apps/device_managaement/api_urls.py
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.device_management.api_views import PublicDeviceViewSet, ParticipantDeviceViewSet


# Create router for ViewSets
router = DefaultRouter()
router.register('public', PublicDeviceViewSet, basename='device-public')
router.register('participant', ParticipantDeviceViewSet, basename='device-participant')

urlpatterns = [
    path('', include(router.urls)),
]