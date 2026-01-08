from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponseForbidden
from apps.core.permissions import participant_required
from .models import Device, DeviceStatus
from .forms import DeviceRegistrationForm


@participant_required
def participant_dashboard(request):
    """Dashboard for system participants to manage their own devices"""
    # Get only devices owned by this participant
    my_devices = Device.objects.filter(created_by=request.user).order_by('-created_at')

    context = {
        'devices': my_devices,
    }

    return render(request, 'device_management/participant_dashboard.html', context)


@participant_required
def add_device(request):
    """
    View for participants to register a new device.
    Creates device with status=PENDING, ready for certificate generation.
    """
    if request.method == 'POST':
        # Pass the current user to the form for duplicate name checking
        form = DeviceRegistrationForm(request.POST, user=request.user)

        if form.is_valid():
            # Create device but don't save yet
            device = form.save(commit=False)

            # Set the owner to current user
            device.created_by = request.user

            # Set initial status to PENDING (waiting for certificate generation)
            device.status = DeviceStatus.PENDING

            # Save the device
            device.save()

            messages.success(
                request,
                f'Device "{device.name}" has been registered successfully! '
                f'Status: {device.get_status_display()}'
            )

            return redirect('participant:dashboard')
    else:
        # GET request - show empty form
        form = DeviceRegistrationForm(user=request.user)

    context = {
        'form': form,
    }

    return render(request, 'device_management/add_device.html', context)


@participant_required
def remove_device(request, device_id):
    """
    Soft delete: Sets device status to REVOKED.
    Only allows participants to remove their own devices.
    Requires POST request with CSRF token for security.
    """
    # Only accept POST requests
    if request.method != 'POST':
        messages.error(request, 'Invalid request method.')
        return redirect('participant:dashboard')

    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to remove this device.')
        return HttpResponseForbidden('You do not have permission to remove this device.')

    # Check if device is already revoked
    if device.status == DeviceStatus.REVOKED:
        messages.warning(request, f'Device "{device.name}" is already revoked.')
        return redirect('participant:dashboard')

    # Soft delete: change status to REVOKED
    device.status = DeviceStatus.REVOKED
    device.save()

    messages.success(
        request,
        f'Device "{device.name}" has been removed (revoked). '
        f'It can no longer send messages to the system.'
    )

    return redirect('participant:dashboard')
