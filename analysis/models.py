from django.db import models
from django.utils import timezone

class WalletConnection(models.Model):
    wallet_address = models.CharField(max_length=255)
    connection_time = models.DateTimeField(default=timezone.now)
    user_agent = models.TextField(null=True, blank=True)
    connection_type = models.CharField(max_length=50)

    class Meta:
        indexes = [
            models.Index(fields=['wallet_address']),
            models.Index(fields=['connection_time']),
        ]

    def __str__(self):
        return f"{self.wallet_address} - {self.connection_time}"


class Transaction(models.Model):
    tx_hash = models.CharField(max_length=255, unique=True)
    from_address = models.CharField(max_length=255)
    to_address = models.CharField(max_length=255)
    value = models.DecimalField(max_digits=30, decimal_places=18)
    timestamp = models.DateTimeField()
    chain = models.CharField(max_length=20)
    
    class Meta:
        indexes = [
            models.Index(fields=['from_address']),
            models.Index(fields=['to_address']),
            models.Index(fields=['timestamp']),
        ]
