# ip_tracking/management/commands/block_ip.py

from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Blocks an IP address by adding it to the BlockedIP model.'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')

    def handle(self, *args, **options):
        ip = options['ip_address']
        if BlockedIP.objects.filter(ip_address=ip).exists():
            self.stdout.write(self.style.WARNING(f"IP {ip} is already blocked."))
        else:
            BlockedIP.objects.create(ip_address=ip)
            self.stdout.write(self.style.SUCCESS(f"Successfully blocked IP: {ip}"))
