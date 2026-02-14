"""
API URLs for messages.
File: apps/data_processing/api_urls.py
"""

from django.urls import path
from .views import DeviceMessageListView

urlpatterns = [
    path('', DeviceMessageListView.as_view(), name='message-list'),
]