from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponseForbidden, HttpResponse
from django.utils import timezone
from datetime import timedelta
from apps.core.permissions import participant_required
from .models import Device, DeviceStatus
from .forms import DeviceRegistrationForm
from .utils import generate_device_certificate


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


@participant_required
def generate_certificate(request, device_id):
    """
    Generate certificate and private key for a device.
    Only allows participants to generate certificates for their own devices.
    Requires POST request with CSRF token for security.
    Status remains PENDING - admin must activate device.
    """
    # Only accept POST requests
    if request.method != 'POST':
        messages.error(request, 'Invalid request method.')
        return redirect('participant:dashboard')

    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to generate a certificate for this device.')
        return HttpResponseForbidden('You do not have permission to generate a certificate for this device.')

    # Check if device is revoked
    if device.status == DeviceStatus.REVOKED:
        messages.error(request, f'Cannot generate certificate for revoked device "{device.name}".')
        return redirect('participant:dashboard')

    # Generate certificate
    try:
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(device)

        # Store certificate information and private key
        device.certificate_pem = cert_pem
        device.private_key_pem = key_pem
        device.certificate_serial = serial_hex
        device.certificate_expiry = expiry_date
        device.certificate_generated_at = timezone.now()
        device.save()

        messages.success(
            request,
            f'Certificate generated successfully for device "{device.name}"! '
            f'You can download the certificate and private key for the next 24 hours. '
            f'Status remains PENDING until admin activates the device.'
        )
    except Exception as e:
        messages.error(request, f'Error generating certificate: {str(e)}')

    return redirect('participant:dashboard')


@participant_required
def download_certificate(request, device_id):
    """
    Download device certificate (.pem file).
    Only available for 24 hours after generation.
    """
    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to download this certificate.')
        return HttpResponseForbidden('You do not have permission to download this certificate.')

    # Check if certificate exists
    if not device.certificate_pem or not device.certificate_generated_at:
        messages.error(request, f'No certificate available for device "{device.name}". Please generate one first.')
        return redirect('participant:dashboard')

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        messages.error(
            request,
            f'Certificate download window expired for device "{device.name}". '
            f'Please regenerate the certificate.'
        )
        return redirect('participant:dashboard')

    # Create HTTP response with certificate file
    response = HttpResponse(device.certificate_pem, content_type='application/x-pem-file')
    response['Content-Disposition'] = f'attachment; filename="{device.name}_certificate.pem"'

    return response


@participant_required
def download_private_key(request, device_id):
    """
    Download device private key (.key file).
    Only available for 24 hours after generation.
    WARNING: Private key is stored temporarily and should be handled securely.
    """
    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to download this private key.')
        return HttpResponseForbidden('You do not have permission to download this private key.')

    # Check if certificate/key exists
    if not device.private_key_pem or not device.certificate_generated_at:
        messages.error(request, f'No private key available for device "{device.name}". Please generate a certificate first.')
        return redirect('participant:dashboard')

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        messages.error(
            request,
            f'Private key download window expired for device "{device.name}". '
            f'Please regenerate the certificate.'
        )
        return redirect('participant:dashboard')

    # Create HTTP response with private key file
    response = HttpResponse(device.private_key_pem, content_type='application/x-pem-file')
    response['Content-Disposition'] = f'attachment; filename="{device.name}_private.key"'

    return response
