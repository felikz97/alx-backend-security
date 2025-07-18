from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=2048)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    detected_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.ip_address} - {self.reason}"
