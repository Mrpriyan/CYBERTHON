# Generated by Django 5.1.4 on 2025-02-08 06:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('analysis', '0001_initial'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='walletconnection',
            name='analysis_wa_ip_addr_b39875_idx',
        ),
        migrations.RemoveField(
            model_name='walletconnection',
            name='ip_address',
        ),
    ]
