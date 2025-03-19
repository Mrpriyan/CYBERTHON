from django.urls import path
from .views import (
    home,
    about,
    forpdf,
    analyze_transactions,
    fetch_all_transaction,
    generate_spider_map,
    fetch_risk_metrics,
)

urlpatterns = [
    path('', home, name='home'),
    path('about/', about, name='about'),
    path('forpdf/', forpdf, name='forpdf'),
    path('analyze/', analyze_transactions, name='analyze_transactions'),
    path('fetch_all_transaction/', fetch_all_transaction, name='fetch_all_transaction'),
    path('generate_spider_map/', generate_spider_map, name='generate_spider_map'),
    path('fetch_risk_metrics/', fetch_risk_metrics, name='fetch_risk_metrics'),
]

