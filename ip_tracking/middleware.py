import requests
from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.core.cache import cache
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Check blacklist
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blacklisted.")

        # Get geolocation data (cached)
        geo_key = f"geo:{ip}"
        geo_data = cache.get(geo_key)
        if not geo_data:
            try:
                res = requests.get(f"http://ip-api.com/json/{ip}").json()
                geo_data = {
                    "country": res.get("country"),
                    "city": res.get("city")
                }
                cache.set(geo_key, geo_data, timeout=86400)  # Cache for 24 hours
            except Exception:
                geo_data = {"country": None, "city": None}

        # Save request log
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path,
            country=geo_data["country"],
            city=geo_data["city"]
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
