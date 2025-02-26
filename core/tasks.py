from celery import shared_task
from .models import Nurse

@shared_task
def check_nurse_level_upgrades():
    """Check and automatically apply nurse level upgrades."""
    nurses = Nurse.objects.filter(is_active=True)
    
    upgrades_count = 0
    upgrade_details = []
    
    for nurse in nurses:
        if nurse.should_upgrade_level():
            old_level = nurse.current_level
            success = nurse.update_level()
            
            if success:
                upgrades_count += 1
                upgrade_details.append(f"{nurse}: {old_level} → {nurse.current_level}")
    
    # Log the results
    result_msg = f"Successfully upgraded {upgrades_count} nurses"
    if upgrade_details:
        result_msg += f":\n" + "\n".join(upgrade_details)
    
    return result_msg