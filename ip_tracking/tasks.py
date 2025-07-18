from celery import shared_task
from django.utils.timezone import now, timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_ips():
    one_hour_ago = now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_counts = {}
    flagged_ips = set()

    for log in logs:
        ip = log.ip_address
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Check for sensitive path access
        if any(log.path.startswith(path) for path in SENSITIVE_PATHS):
            if not SuspiciousIP.objects.filter(ip_address=ip).exists():
                SuspiciousIP.objects.create(
                    ip_address=ip,
                    reason=f"Accessed sensitive path: {log.path}"
                )
                flagged_ips.add(ip)

    # Flag IPs with >100 requests in 1 hour
    for ip, count in ip_counts.items():
        if count > 100 and ip not in flagged_ips:
            if not SuspiciousIP.objects.filter(ip_address=ip).exists():
                SuspiciousIP.objects.create(
                    ip_address=ip,
                    reason=f"Exceeded 100 requests in one hour ({count} requests)"
                )
