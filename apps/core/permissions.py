from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.contrib import messages
from .models import UserProfile


def participant_required(view_func):
    """Decorator to require System Participant user type"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not hasattr(request.user, 'profile'):
            raise PermissionDenied("User profile not found")

        if request.user.profile.user_type != UserProfile.UserType.PARTICIPANT:
            messages.error(request, "You must be a System Participant to access this page")
            return redirect('dashboard:index')

        return view_func(request, *args, **kwargs)
    return wrapper


def admin_required(view_func):
    """Decorator to require Admin user type"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            messages.error(request, "Administrator access required")
            return redirect('dashboard:index')

        return view_func(request, *args, **kwargs)
    return wrapper


def non_participant_or_higher(view_func):
    """Decorator to require at least Non-Participant access (anyone logged in)"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not hasattr(request.user, 'profile'):
            raise PermissionDenied("User profile not found")

        return view_func(request, *args, **kwargs)
    return wrapper


# Class-based view mixins
from django.contrib.auth.mixins import LoginRequiredMixin


class ParticipantRequiredMixin(LoginRequiredMixin):
    """Mixin to require System Participant user type for class-based views"""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        if not hasattr(request.user, 'profile'):
            raise PermissionDenied("User profile not found")

        if request.user.profile.user_type != UserProfile.UserType.PARTICIPANT:
            messages.error(request, "You must be a System Participant to access this page")
            return redirect('dashboard:index')

        return super().dispatch(request, *args, **kwargs)


class AdminRequiredMixin(LoginRequiredMixin):
    """Mixin to require Admin user type for class-based views"""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        if not request.user.is_staff and not request.user.is_superuser:
            messages.error(request, "Administrator access required")
            return redirect('dashboard:index')

        return super().dispatch(request, *args, **kwargs)
