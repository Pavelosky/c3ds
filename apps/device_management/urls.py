from django.urls import path
from . import views

app_name = 'participant'

urlpatterns = [
    path('dashboard/', views.participant_dashboard, name='dashboard'),
]
