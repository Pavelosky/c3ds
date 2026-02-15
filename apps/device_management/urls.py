from django.urls import path
from . import views

app_name = 'participant'

# Legacy file download endpoints
# These remain as session-authenticated views for certificate/key downloads
# React frontend can call these endpoints with session cookies
urlpatterns = [
    path('device/<uuid:device_id>/download-certificate/', views.download_certificate, name='download_certificate'),
    path('device/<uuid:device_id>/download-private-key/', views.download_private_key, name='download_private_key'),
]
