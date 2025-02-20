import os
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator,MaxLengthValidator
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.timezone import localtime
from django.core.files.storage import default_storage
# Create your models here.

class Roles(models.Model):
    role_name = models.CharField(50)
    created_at = models.DateTimeField(default=timezone.now, null=False)
        
    def __str__(self):
        return self.role_name
    
    class Meta:
        db_table = 'roles'
        
class User(AbstractUser):
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    role = models.ForeignKey(Roles, on_delete=models.SET_NULL, null=True)
    phone = models.CharField(max_length=16, blank=True)
    is_login = models.BooleanField(default=False)
    reset_password_token = models.CharField(max_length=100, blank=True, null=True)
    reset_password_expire = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
        # Add related_name to avoid clashes
    def __str__(self):
        return f'{self.username} - {self.role}'
    
    def tokens(self):    
        refresh = RefreshToken.for_user(self)
        return {
            "refresh":str(refresh),
            "access":str(refresh.access_token)
        }
  
    class Meta:
        db_table = "users"
        
class LevelReference(models.Model):
    level = models.CharField(max_length=10, unique=True)
    next_level = models.CharField(max_length=10,null=True)
    required_time_in_month = models.IntegerField(null=False)
    created_at = models.DateTimeField(default=timezone.now)
    update_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['level']
        db_table = 'level_reference'
        
    def __str__(self):
        return self.level
    
    def get_next_level(self):
        return LevelReference.objects.filter(id__gt=self.id).first()
           
class Department(models.Model):
    department = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'department'    
    
    def __str__(self):
        return self.department

class Nurse(models.Model):
    nurse_account_id = models.CharField(max_length=50, null=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.BinaryField(null=True, blank=True)
    current_level = models.ForeignKey(LevelReference, on_delete=models.SET_NULL, null=True)
    hire_date = models.DateField()
    years_of_service = models.IntegerField()
    level_upgrade_date = models.DateField(auto_now=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    specialization = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.nurse_account_id + " - " + self.user.first_name + " " + self.user.last_name

    class Meta:
        ordering = ['nurse_account_id']
        db_table = 'nurse'

class LevelUpgradeStatus(models.Model):
    status_name = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'level_upgrade_status'
        
    def __str__(self):
        return self.status_name

class LevelHistory(models.Model):
    """Track level changes for audit purposes"""
    nurse = models.ForeignKey(Nurse, on_delete=models.CASCADE)
    from_level = models.ForeignKey(LevelReference, on_delete=models.SET_NULL, null=True, related_name='from_level')
    to_level = models.ForeignKey(LevelReference, on_delete=models.SET_NULL, null=True, related_name='to_level')
    change_date = models.DateField(auto_now_add=True)
    years_of_service = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    status = models.ForeignKey(LevelUpgradeStatus, on_delete=models.SET_NULL, null=True)


    
    class Meta:
        ordering = ['nurse']
        db_table = 'level_history'
        
    def __str__(self):
        return f"{self.nurse} from {self.from_level} to {self.to_level} - {self.status}"

class Management(models.Model):
    management_account_id = models.CharField(max_length=50, null=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    position = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.management_account_id + " - " + self.user.first_name + " " + self.user.last_name

    
    class Meta:
        ordering = ['management_account_id']
        db_table = 'management'
    
class ConsultationTypes(models.Model):
    name = models.CharField(max_length=100,null=False)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'consultation_type'

class ConsultationStatus(models.Model):
    name = models.CharField(max_length=100,null=False)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    
    
    class Meta:
        db_table = 'consultation_status'    
       
class Consultations(models.Model):
    title = models.CharField(max_length=200,null=False)
    nurses_id = models.ManyToManyField(Nurse)
    management = models.ForeignKey(Management, on_delete=models.SET_NULL, null=True)
    consultation_type = models.ForeignKey(ConsultationTypes, on_delete=models.SET_NULL, null=True)
    description = models.TextField(blank=True)
    scheduled_date = models.DateTimeField()
    status = models.ForeignKey(ConsultationStatus, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['scheduled_date']
        db_table = 'consultations'

class Materials(models.Model):
    title = models.CharField(max_length=200, null=True, blank=True)
    file_path = models.FileField(upload_to="documnets/")
    size = models.PositiveBigIntegerField(editable=True, null=True, blank=True)
    size_readable = models.CharField(max_length=20, editable=True, null=True, blank=True)  # human-readable size
    created_at = models.DateTimeField(auto_now_add=True)


    def save(self, *args, **kwargs):
        # Save the object first so the file is available

        
        if self.file_path and not self.title:
            self.title = os.path.basename(self.file_path.name)
        super().save(*args,**kwargs)
        
        if self.file_path:
            file_path = self.file_path.path
            print(self.file_path,file_path)
            if os.path.exists(file_path):
                self.size  = os.path.getsize(file_path)
                self.size_readable = self._calculate_human_readable_size(self.size)
                super().save(update_fields=["size", "size_readable"])

    def delete(self, *args, **kwargs):
        """Delete file from storage when instance is deleted."""
        if self.file_path:
            file_path = self.file_path.path
            if os.path.exists(file_path):
                default_storage.delete(file_path)
        super().delete(*args, **kwargs)
    
    @property
    def formatted_created_at(self):
       return localtime(self.created_at).strftime('%d/%m/%Y, %H:%M')     
                            
    def _calculate_human_readable_size(self, size):
        """Convert size in bytes to a human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    
    def __str__(self):
        return f"{self.title} ({self.size_readable})"
    
    class Meta:
        db_table = 'materials'

class CounselingMaterials(models.Model):
    counseling = models.ForeignKey(Consultations, on_delete=models.CASCADE, null=True)
    description = models.TextField()
    file = models.ManyToManyField(Materials,related_name="counseling_materials")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
 
    def __str__(self):
        return self.counseling.title   
    
    class Meta:
        db_table = 'counseling_materials'
        

class ConsultationResult(models.Model):
    consultation = models.ForeignKey(Consultations, on_delete=models.CASCADE)
    nurse = models.ForeignKey(Nurse, on_delete=models.SET_NULL, null=True)
    nurse_feedback = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    class Meta:
        db_table = 'consultation_result'
        
class MaterialReadStatus(models.Model):
    consultation_materials = models.ForeignKey(CounselingMaterials, on_delete=models.SET_NULL, null=True)
    nurse = models.ForeignKey(Nurse, on_delete=models.SET_NULL, null=True)
    read_at = models.DateTimeField()
    
    class Meta:
        db_table = 'material_read_status'
                
class LevelUpgradeRequests(models.Model):
    nurse = models.ForeignKey(Nurse, on_delete=models.SET_NULL, null=True)
    management = models.ForeignKey(Management, on_delete=models.SET_NULL, null=True)
    requested_level = models.ForeignKey(LevelReference, on_delete=models.SET_NULL, null=True, related_name='requested_level_requests')
    current_level = models.ForeignKey(LevelReference, on_delete=models.SET_NULL, null=True, related_name='current_level_requests')
    request_date = models.DateField(auto_now_add=True)
    status = models.ForeignKey(LevelUpgradeStatus, on_delete=models.SET_NULL, null=True)
    is_approve = models.BooleanField(default=False)
    approval_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    class Meta:
        ordering = ['request_date']
        db_table = 'level_upgrade_requests'
        
class Notificaitons(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notificaitons'
              
class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action_type = models.CharField(max_length=20,null=False)
    table_name = models.CharField(max_length=100,null=False)
    record_id = models.IntegerField()
    old_value = models.TextField()
    new_value = models.TextField()
    ip_address = models.CharField(max_length=100)
    timestamp = models.TimeField()
    
    class Meta:
        ordering = ['timestamp'] 
        db_table ='auditlog'
        
class LoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    login_time = models.DateTimeField()
    logout_time = models.DateTimeField()
    ip_address = models.CharField(max_length=100)
    device_info = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'loginhistory'

class SystemConfiguration(models.Model):
    config_key = models.CharField(max_length=50)
    config_value = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta: 
        db_table = 'system_configuration'
        
        