from django.urls import path
from .views import fetch_all_transaction, home, analyze_transactions, about, forpdf

urlpatterns = [
    path('', home, name='home'),
    path('analyze_transactions/', analyze_transactions, name='analyze_transactions'),
    path('about/', about, name='about'),
    path('forpdf/', forpdf, name='forpdf'),
    path('fetch_all_transaction/', fetch_all_transaction, name='fetch_all_transaction'),
]