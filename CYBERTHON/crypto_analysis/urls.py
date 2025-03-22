# crypto_analysis/urls.py (project level)
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('analysis.urls')),  # Changed to your actual app name 'analysis'
    
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)