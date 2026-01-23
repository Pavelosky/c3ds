from django.urls import path
from . import views

app_name = 'participant'

urlpatterns = [
    path('dashboard/', views.participant_dashboard, name='dashboard'),
    path('device/add/', views.add_device, name='add_device'),
    path('device/<uuid:device_id>/remove/', views.remove_device, name='remove_device'),
    path('device/<uuid:device_id>/generate-certificate/', views.generate_certificate, name='generate_certificate'),
    path('device/<uuid:device_id>/download-certificate/', views.download_certificate, name='download_certificate'),
    path('device/<uuid:device_id>/download-private-key/', views.download_private_key, name='download_private_key'),
    path('device/<uuid:device_id>/download-code/', views.download_device_code, name='download_device_code'),
]
