"""
API views for device management.
File: apps/device_management/api_views.py

Uses DRF ViewSets for full CRUD operations on devices.
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from apps.device_management.models import Device
from apps.device_management.serializers import (
    DeviceListSerializer,
    DeviceDetailSerializer,
    DeviceRegistrationSerializer,
)


class PublicDeviceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public read-only access to all devices.
    
    Endpoints:
    - GET /api/v1/devices/public/           - List all devices (paginated)
    - GET /api/v1/devices/public/{id}/      - Device detail
    
    Features:
    - No authentication required
    - Filtering by status, device_type
    - Searching by name, location
    - Ordering by created_at, updated_at, name
    - Pagination (25 per page)
    
    Examples:
    - /api/v1/devices/public/?status=ACTIVE
    - /api/v1/devices/public/?search=ESP32
    - /api/v1/devices/public/?ordering=-created_at
    """
    permission_classes = [AllowAny]
    queryset = Device.objects.select_related('created_by').all()
    
    # Enable filtering, searching, ordering
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'device_type']
    search_fields = ['name', 'latitude', 'longitude']
    ordering_fields = ['created_at', 'updated_at', 'name']
    ordering = ['-created_at']  # Default: newest first

    def get_serializer_class(self):
        """Use detailed serializer for single device, list serializer for list."""
        if self.action == 'retrieve':
            return DeviceDetailSerializer
        return DeviceListSerializer