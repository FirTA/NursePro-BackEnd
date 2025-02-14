from django.contrib import admin
from .models import (
    User,
    Nurse,
    Management,
    Department,
    LevelReference,
    LevelHistory,
    LevelUpgradeRequests,
    LevelUpgradeStatus,
    MaterialReadStatus,
    ConsultationMaterials,
    ConsultationResult,
    Consultations,
    ConsultationTypes,
    ConsultationStatus,
    AuditLog,
    SystemConfiguration,
)

# Register your models here.

admin.site.register(User)
admin.site.register(Nurse)
admin.site.register(Management)
admin.site.register(Department)
admin.site.register(LevelReference)
admin.site.register(LevelUpgradeRequests)
admin.site.register(LevelHistory)
admin.site.register(LevelUpgradeStatus)
admin.site.register(MaterialReadStatus)
admin.site.register(ConsultationMaterials)
admin.site.register(Consultations)
admin.site.register(ConsultationResult)
admin.site.register(ConsultationTypes)
admin.site.register(ConsultationStatus)
admin.site.register(AuditLog)
admin.site.register(SystemConfiguration)