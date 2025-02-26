from django.core.management.base import BaseCommand
from core.models import Nurse

class Command(BaseCommand):
    help = 'Check and apply automatic nurse level upgrades'
    
    def handle(self, *args, **options):
        nurses = Nurse.objects.filter(is_active=True)
        
        upgrades_count = 0
        for nurse in nurses:
            if nurse.should_upgrade_level():
                success = nurse.update_level()
                if success:
                    upgrades_count += 1
                    self.stdout.write(f"Upgraded {nurse} to {nurse.current_level}")
        
        self.stdout.write(self.style.SUCCESS(f'Successfully upgraded {upgrades_count} nurses'))
