from django.shortcuts import render
from apps.data_processing.models import DeviceMessage
from apps.device_management.models import Device

# Create your views here.

def dashboard_view(request):
    """
    View to display a dashboard of device messages.
    """
    # Get 100 latest messages
    messages = DeviceMessage.objects.select_related('device').all()
    
    # apply filters
    device_filter = request.GET.get('device')
    if device_filter:
        messages = messages.filter(device_id=device_filter)

    status_filter = request.GET.get('status')
    if status_filter:
        messages = messages.filter(device__status=status_filter)
    
    date_filter = request.GET.get('date')
    if date_filter:
        messages = messages.filter(timestamp__date=date_filter)

    # Get all devices
    devices = Device.objects.all()

    context = {
        'messages': messages,
        'devices': devices,
    }

    return render(request, 'dashboard/index.html', context)
