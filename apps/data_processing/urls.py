from django.urls import path
from .views import DeviceMessageView

urlpatterns = [
    path('message/', DeviceMessageView.as_view(), name='device-message'),
]