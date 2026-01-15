"""
API views for public dashboard.
File: apps/dashboard/api_views.py

REST API endpoints for dashboard statistics and data.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.utils import timezone
from datetime import timedelta

from apps.device_management.models import Device
from apps.data_processing.models import DeviceMessage
from apps.dashboard.serializers import DashboardStatsSerializer


class DashboardStatsView(APIView):
    """
    GET /api/v1/dashboard/stats/

    Returns aggregated statistics for public dashboard.
    No authentication required (public data).

    Example response:
    {
        "total_devices": 15,
        "active_devices": 12,
        "pending_devices": 2,
        "revoked_devices": 1,
        "total_messages": 1542,
        "messages_today": 142,
        "messages_this_week": 987
    }
    """
    permission_classes = [AllowAny]  # Public endpoint

    def get(self, request):
        """Calculate and return dashboard statistics."""
        
        # Get current time and calculate time windows
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)

        # Device counts by status
        total_devices = Device.objects.count()
        active_devices = Device.objects.filter(status='ACTIVE').count()
        pending_devices = Device.objects.filter(status='PENDING').count()
        revoked_devices = Device.objects.filter(status='REVOKED').count()

        # Message counts
        total_messages = DeviceMessage.objects.count()
        messages_today = DeviceMessage.objects.filter(
            recieved_at__gte=today_start
        ).count()
        messages_this_week = DeviceMessage.objects.filter(
            recieved_at__gte=week_start
        ).count()

        # Prepare data dictionary
        stats = {
            'total_devices': total_devices,
            'active_devices': active_devices,
            'pending_devices': pending_devices,
            'revoked_devices': revoked_devices,
            'total_messages': total_messages,
            'messages_today': messages_today,
            'messages_this_week': messages_this_week,
        }

        # Serialize and return
        serializer = DashboardStatsSerializer(stats)
        return Response(serializer.data)