"""
URL configuration for admin API endpoints.
All routes are mounted under /api/v1/admin/ in config/urls.py.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .api_views import (
    AnomalyFlagViewSet,
    AnomalySummaryView,
    EventCorrelationView,
    IncidentViewSet,
    AdminMessageTimelineView,
    DetectionHeatmapView,
    DeviceComparisonView,
    DeviceAuditTrailView,
    AdminDeviceListView,
    AdminDeviceSetStatusView,
    MessageRateView,
    SystemHealthView,
    DeviceCommandView,
    CommandQueueView,
    DetectionPolicyView,
    DetectionPolicyDetailView,
    PolicyTriggerLogView,
)

router = DefaultRouter()
router.register('anomaly-flags', AnomalyFlagViewSet, basename='anomaly-flag')
router.register('incidents', IncidentViewSet, basename='incident')

urlpatterns = [
    path('anomaly-flags/summary/', AnomalySummaryView.as_view(), name='anomaly-summary'),
    path('', include(router.urls)),
    path('events/<int:message_id>/correlate/', EventCorrelationView.as_view(), name='event-correlate'),
    path('messages/timeline/', AdminMessageTimelineView.as_view(), name='admin-message-timeline'),
    path('heatmap/', DetectionHeatmapView.as_view(), name='detection-heatmap'),
    path('devices/compare/', DeviceComparisonView.as_view(), name='device-compare'),
    path('devices/<uuid:device_id>/audit/', DeviceAuditTrailView.as_view(), name='device-audit'),
    path('devices/', AdminDeviceListView.as_view(), name='admin-device-list'),
    path('devices/<uuid:device_id>/set-status/', AdminDeviceSetStatusView.as_view(), name='admin-device-set-status'),
    path('devices/<uuid:device_id>/commands/', DeviceCommandView.as_view(), name='device-commands'),
    path('commands/', CommandQueueView.as_view(), name='command-queue'),
    path('messages/rate/', MessageRateView.as_view(), name='message-rate'),
    path('system/health/', SystemHealthView.as_view(), name='system-health'),
    path('policies/', DetectionPolicyView.as_view(), name='policy-list'),
    path('policies/<uuid:policy_id>/', DetectionPolicyDetailView.as_view(), name='policy-detail'),
    path('policies/<uuid:policy_id>/triggers/', PolicyTriggerLogView.as_view(), name='policy-triggers'),
]
