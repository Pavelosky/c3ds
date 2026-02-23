"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),

    # Device Management (legacy file download endpoints - still needed)
    path('participant/', include('apps.device_management.urls')),

    # Device Message Ingestion (CRITICAL - external devices use this)
    path('api/device/', include('apps.data_processing.urls')),

    # API URLs (for React frontend)
    path('api/v1/', include([
        path('dashboard/', include('apps.dashboard.api_urls')),
        path('devices/', include('apps.device_management.api_urls')),
        path('messages/', include('apps.data_processing.api_urls')),
        path('auth/', include('apps.core.api_urls')),
        path('admin/', include('apps.anomaly_detection.api_urls')),    # Admin API
    ])),

    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    # SPA Fallback
    # Serves index.html for all routes that DON'T start with api/admin/participant/static
    # React Router handles client-side routing from here.
    # React admin pages use /c3ds-admin/* to avoid collision with Django's /admin/.
    re_path(r'^(?!api|admin|participant|static).*$', TemplateView.as_view(template_name='index.html'), name='react-app'),
]
