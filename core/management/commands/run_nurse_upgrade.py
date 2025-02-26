from django.core.management.base import BaseCommand
from core.tasks import check_nurse_level_upgrades

class Command(BaseCommand):
    help = 'Manually run nurse level upgrades check'
    
    def handle(self, *args, **options):
        result = check_nurse_level_upgrades()
        self.stdout.write(self.style.SUCCESS(result))