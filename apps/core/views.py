from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from .forms import UserRegistrationForm, UserLoginForm
from .models import UserProfile


def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.profile.user_type = form.cleaned_data['user_type']
            user.profile.save()

            login(request, user)
            messages.success(request, f'Welcome {user.username}! Your account has been created.')

            # Redirect based on user type
            if user.profile.user_type == 'PARTICIPANT':
                return redirect('participant:dashboard')
            else:
                return redirect('dashboard:index')
    else:
        form = UserRegistrationForm()

    return render(request, 'core/register.html', {'form': form})


def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            remember_me = form.cleaned_data.get('remember_me')

            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)

                # Handle "remember me" functionality
                if not remember_me:
                    # Session expires when browser closes
                    request.session.set_expiry(0)
                else:
                    # Session expires after 2 weeks
                    request.session.set_expiry(1209600)  # 2 weeks in seconds

                messages.success(request, f'Welcome back, {user.username}!')

                # Smart redirect: check 'next' parameter first, then user type
                next_url = request.GET.get('next')
                if next_url:
                    return redirect(next_url)

                # Fall back to user-type-based redirect
                if hasattr(user, 'profile') and user.profile.user_type == UserProfile.UserType.PARTICIPANT:
                    return redirect('participant:dashboard')
                else:
                    return redirect('dashboard:index')
    else:
        form = UserLoginForm()

    return render(request, 'core/login.html', {'form': form})
