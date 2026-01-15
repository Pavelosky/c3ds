"""
API URLs for dashboard.
File: apps/dashboard/api_urls.py
"""

from django.urls import path
from apps.dashboard.api_views import DashboardStatsView

urlpatterns = [
    path('stats/', DashboardStatsView.as_view(), name='api-dashboard-stats'),
]