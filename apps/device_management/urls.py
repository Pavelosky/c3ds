from django.urls import path
from . import views

app_name = 'participant'

urlpatterns = [
    path('dashboard/', views.participant_dashboard, name='dashboard'),
    path('device/add/', views.add_device, name='add_device'),
    path('device/<uuid:device_id>/remove/', views.remove_device, name='remove_device'),
]
