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
    CounselingMaterials,
    ConsultationResult,
    Consultations,
    ConsultationTypes,
    ConsultationStatus,
    AuditLog,
    SystemConfiguration,
    Materials
)
from django.utils.safestring import mark_safe
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
admin.site.register(Consultations)
admin.site.register(ConsultationResult)
admin.site.register(ConsultationTypes)
admin.site.register(ConsultationStatus)
admin.site.register(AuditLog)
admin.site.register(SystemConfiguration)
# admin.site.register(Materials)

@admin.register(Materials)
class MaterialsAdmin(admin.ModelAdmin):
    list_display = ("title", "file_path", "size", "size_readable","created_at")  # Make sure size_readable is here


@admin.register(CounselingMaterials)
class MaterialsAdmin(admin.ModelAdmin):
    list_display = ("counseling", "description", "get_files", "created_at","updated_at")  # Make sure size_readable is here
    
    def get_files(self, obj):
        """Display all related file names as a comma-separated list."""
        files = [file.title for file in obj.file.all()]
        return mark_safe("<br>".join(files)) if files else "-"  # Assuming `file` is ManyToManyField with `Materials`
    get_files.short_description = "Files"