from django.shortcuts import render
from apps.core.permissions import participant_required
from .models import Device


@participant_required
def participant_dashboard(request):
    """Dashboard for system participants to manage their own devices"""
    # Get only devices owned by this participant
    my_devices = Device.objects.filter(created_by=request.user).order_by('-created_at')

    context = {
        'devices': my_devices,
    }

    return render(request, 'device_management/participant_dashboard.html', context)
