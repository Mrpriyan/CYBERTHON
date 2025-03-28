from django.urls import path
from .views import (
    home,
    about,
    forpdf,
    ip_analysis,
    analyze_transactions,
    fetch_all_transaction,
    generate_spider_map,
    fetch_risk_metrics,
    download_raw_data,
    download_filtered_data,
)

urlpatterns = [
    path('', home, name='home'),
    path('about/', about, name='about'),
    path("ip-analysis/", ip_analysis, name="ip_analysis"),
    path('forpdf/', forpdf, name='forpdf'),
    path('analyze/', analyze_transactions, name='analyze_transactions'),
    path('fetch_all_transaction/', fetch_all_transaction, name='fetch_all_transaction'),
    path('generate_spider_map/', generate_spider_map, name='generate_spider_map'),
    path('fetch_risk_metrics/', fetch_risk_metrics, name='fetch_risk_metrics'),
    path('download_raw_data/', download_raw_data, name='download_raw_data'),
    path('download_filtered_data/', download_filtered_data, name='download_filtered_data'),
]