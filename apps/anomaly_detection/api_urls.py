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
]
