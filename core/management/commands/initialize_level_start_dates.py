from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import Nurse  # Replace 'yourapp' with your actual app name


class Command(BaseCommand):
    help = 'Initialize current_level_start_date for all nurses'

    def handle(self, *args, **options):
        nurses = Nurse.objects.filter(current_level_start_date__isnull=True)
        count = nurses.count()
        
        self.stdout.write(f"Found {count} nurses that need current_level_start_date initialized.")
        
        for nurse in nurses:
            nurse.current_level_start_date = nurse.hire_date
            nurse.save(update_fields=['current_level_start_date'])
            
        self.stdout.write(self.style.SUCCESS(f"Successfully initialized current_level_start_date for {count} nurses."))