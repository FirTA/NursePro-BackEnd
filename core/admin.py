from django.contrib import admin
from .models import *

@admin.register(Roles)
class RolesAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'is_active', 'is_login', 'created_at')
    list_filter = ('role', 'is_active', 'is_login')
    search_fields = ('username', 'email', 'first_name', 'last_name')

@admin.register(LevelReference)
class LevelReferenceAdmin(admin.ModelAdmin):
    list_display = ('level', 'next_level', 'required_time_in_month', 'created_at')
    search_fields = ('level', 'next_level')

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)

@admin.register(Nurse)
class NurseAdmin(admin.ModelAdmin):
    list_display = ('nurse_account_id', 'user', 'current_level', 'hire_date', 
                   'years_of_service', 'level_upgrade_date', 'department', 'is_active')
    list_filter = ('current_level', 'department', 'is_active')
    search_fields = ('nurse_account_id', 'user__username', 'user__email')
    readonly_fields = ('years_of_service', 'level_upgrade_date')  # Make these read-only since they're auto-calculated
    
@admin.register(LevelUpgradeStatus)
class LevelUpgradeStatusAdmin(admin.ModelAdmin):
    list_display = ('status_name', 'created_at')
    search_fields = ('status_name',)

@admin.register(LevelHistory)
class LevelHistoryAdmin(admin.ModelAdmin):
    list_display = ('nurse', 'from_level', 'to_level', 'change_date', 'status')
    list_filter = ('from_level', 'to_level', 'status')
    search_fields = ('nurse__nurse_account_id',)

@admin.register(Management)
class ManagementAdmin(admin.ModelAdmin):
    list_display = ('management_account_id', 'user', 'department', 'position', 'is_active')
    list_filter = ('department', 'is_active')
    search_fields = ('management_account_id', 'user__username', 'position')

@admin.register(CounselingTypes)
class CounselingTypesAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)

@admin.register(CounselingStatus)
class CounselingStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)

@admin.register(Materials)
class MaterialsAdmin(admin.ModelAdmin):
    list_display = ('title', 'file_path', 'size', 'size_readable', 'created_at')
    search_fields = ('title',)
    readonly_fields = ('size', 'size_readable')

@admin.register(Counseling)
class CounselingAdmin(admin.ModelAdmin):
    list_display = ('title', 'management', 'counseling_type', 'scheduled_date', 'status')
    list_filter = ('counseling_type', 'status')
    search_fields = ('title', 'management__management_account_id')
    filter_horizontal = ('nurses_id', 'material_files')

@admin.register(CounselingMaterials)
class CounselingMaterialsAdmin(admin.ModelAdmin):
    list_display = ('counseling', 'created_at')
    search_fields = ('counseling__title',)
    filter_horizontal = ('file',)

@admin.register(CounselingResult)
class CounselingResultAdmin(admin.ModelAdmin):
    list_display = ('consultation', 'nurse', 'created_at')
    list_filter = ('consultation__status',)
    search_fields = ('consultation__title', 'nurse__nurse_account_id')

@admin.register(MaterialReadStatus)
class MaterialReadStatusAdmin(admin.ModelAdmin):
    list_display = ('consultation_materials', 'nurse', 'read_at')
    list_filter = ('read_at',)
    search_fields = ('nurse__nurse_account_id',)

@admin.register(LevelUpgradeRequests)
class LevelUpgradeRequestsAdmin(admin.ModelAdmin):
    list_display = ('nurse', 'management', 'requested_level', 'current_level', 'status', 'is_approve', 'request_date')
    list_filter = ('status', 'is_approve')
    search_fields = ('nurse__nurse_account_id', 'management__management_account_id')

@admin.register(Notificaitons)
class NotificaitonsAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'created_at')
    search_fields = ('user__username', 'message')

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action_type', 'table_name', 'record_id', 'ip_address', 'timestamp')
    list_filter = ('action_type', 'table_name')
    search_fields = ('user__username', 'table_name')

@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'login_time', 'logout_time', 'ip_address', 'device_info', 'status')
    list_filter = ('status',)
    search_fields = ('user__username', 'ip_address')

@admin.register(SystemConfiguration)
class SystemConfigurationAdmin(admin.ModelAdmin):
    list_display = ('config_key', 'config_value', 'created_at')
    search_fields = ('config_key',)