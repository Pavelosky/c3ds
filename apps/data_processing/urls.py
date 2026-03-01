from django.urls import path
from .views import DeviceMessageView, DeviceCommandAckView

urlpatterns = [
    path('message/', DeviceMessageView.as_view(), name='device-message'),
    path('ack/', DeviceCommandAckView.as_view(), name='device-command-ack'),
]