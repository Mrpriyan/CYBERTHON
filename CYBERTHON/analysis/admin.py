
# admin.py
from django.contrib import admin
from .models import WalletConnection, Transaction

@admin.register(WalletConnection)
class WalletConnectionAdmin(admin.ModelAdmin):
    list_display = ('wallet_address', 'connection_time')
    search_fields = ('wallet_address',)
    list_filter = ('connection_time', 'connection_type')


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('tx_hash', 'from_address', 'to_address', 'value', 'chain')
    search_fields = ('tx_hash', 'from_address', 'to_address')
    list_filter = ('chain', 'timestamp')