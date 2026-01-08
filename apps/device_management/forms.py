from django import forms
from .models import Device, DeviceType
from decimal import Decimal


class DeviceRegistrationForm(forms.ModelForm):
    """
    Form for participants to register new IoT devices.
    Includes validation for geographic coordinates and unique device names per user.
    """

    def __init__(self, *args, **kwargs):
        """
        Store the user who is creating the device for duplicate name checking.
        """
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    class Meta:
        model = Device
        fields = ['name', 'description', 'device_type', 'latitude', 'longitude']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., Sensor-Vilnius-001'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Optional notes about this device'
            }),
            'device_type': forms.Select(attrs={
                'class': 'form-control'
            }),
            'latitude': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., 54.687157',
                'step': '0.000001'
            }),
            'longitude': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., 25.279652',
                'step': '0.000001'
            }),
        }
        help_texts = {
            'name': 'A unique name to identify your device',
            'latitude': 'Latitude coordinate between -90 and 90',
            'longitude': 'Longitude coordinate between -180 and 180',
        }

    def clean_name(self):
        """
        Validate device name length and uniqueness per user.
        """
        name = self.cleaned_data.get('name')

        if not name:
            raise forms.ValidationError('Device name is required.')

        # Check length constraints
        if len(name) < 3:
            raise forms.ValidationError(
                'Device name must be at least 3 characters long.'
            )

        if len(name) > 50:
            raise forms.ValidationError(
                'Device name must not exceed 50 characters.'
            )

        # Check for duplicate names for the same user
        if self.user:
            duplicate_exists = Device.objects.filter(
                name=name,
                created_by=self.user
            ).exists()

            if duplicate_exists:
                raise forms.ValidationError(
                    'You already have a device with this name. Please choose a different name.'
                )

        return name

    def clean_latitude(self):
        """
        Validate latitude is within valid range (-90 to 90).
        """
        latitude = self.cleaned_data.get('latitude')

        if latitude is None:
            raise forms.ValidationError('Latitude is required.')

        if latitude < Decimal('-90') or latitude > Decimal('90'):
            raise forms.ValidationError(
                'Latitude must be between -90 and 90 degrees.'
            )

        return latitude

    def clean_longitude(self):
        """
        Validate longitude is within valid range (-180 to 180).
        """
        longitude = self.cleaned_data.get('longitude')

        if longitude is None:
            raise forms.ValidationError('Longitude is required.')

        if longitude < Decimal('-180') or longitude > Decimal('180'):
            raise forms.ValidationError(
                'Longitude must be between -180 and 180 degrees.'
            )

        return longitude
