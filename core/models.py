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
from dateutil.relativedelta import relativedelta
from django.utils import timezone
# Create your models here.

class Roles(models.Model):
    name = models.CharField(50)
    created_at = models.DateTimeField(default=timezone.now, null=False)
        
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'roles'
        
class User(AbstractUser):
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    role = models.ForeignKey(Roles, on_delete=models.SET_NULL, null=True)
    phone = models.CharField(max_length=16, blank=True)
    profile_picture = models.BinaryField(null=True, blank=True)
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
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'department'    
    
    def __str__(self):
        return self.name

class Nurse(models.Model):
    nurse_account_id = models.CharField(max_length=50, null=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    current_level = models.ForeignKey(LevelReference, on_delete=models.SET_NULL, null=True)
    hire_date = models.DateField()
    years_of_service = models.IntegerField()
    level_upgrade_date = models.DateField(null=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    specialization = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.nurse_account_id + " - " + self.user.first_name + " " + self.user.last_name

    def calculate_years_of_service(self):
        if self.hire_date:
            today = timezone.now().date()
            difference = relativedelta(today, self.hire_date)
            # Convert to total months
            return (difference.years * 12) + difference.months
        return 0
    
    def should_upgrade_level(self):
        """Check if nurse should be upgraded based on level_upgrade_date"""
        if self.level_upgrade_date and self.current_level:
            return timezone.now().date() >= self.level_upgrade_date
        return False
    
    def get_next_level(self):
        """Get the next level from LevelReference"""
        if self.current_level:
            next_level = LevelReference.objects.filter(
                level=self.current_level.next_level
            ).first()
            return next_level
        return None
    
    def update_level_and_date(self):
        """Update current level and calculate new upgrade date"""
        next_level = self.get_next_level()
        if next_level:
            # Create level history record
            LevelHistory.objects.create(
                nurse=self,
                from_level=self.current_level,
                to_level=next_level,
                years_of_service=self.years_of_service,
                status=LevelUpgradeStatus.objects.get(status_name='Automatic')  # You'll need this status in your DB
            )
            
            # Update to new level
            self.current_level = next_level
            
            # Calculate new upgrade date
            self.level_upgrade_date = timezone.now().date() + relativedelta(months=next_level.required_time_in_month)

    def save(self, *args, **kwargs):
        
        if not self.pk:  # New nurse
            super().save(*args, **kwargs)
        else:  # Existing nurse
            if self.should_upgrade_level():
                self.update_level_and_date()
        
        self.years_of_service = self.calculate_years_of_service()
        if self.hire_date and self.current_level:
            required_months = self.current_level.required_time_in_month
            self.level_upgrade_date = self.hire_date + relativedelta(months=required_months)
            
        super().save(*args, **kwargs)

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
    
class CounselingTypes(models.Model):
    name = models.CharField(max_length=100,null=False)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'counseling_type'

class CounselingStatus(models.Model):
    name = models.CharField(max_length=100,null=False)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    
    
    class Meta:
        db_table = 'counseling_status'    
        
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
       
class Counseling(models.Model):
    title = models.CharField(max_length=200,null=False)
    nurses_id = models.ManyToManyField(Nurse)
    management = models.ForeignKey(Management, on_delete=models.SET_NULL, null=True)
    counseling_type = models.ForeignKey(CounselingTypes, on_delete=models.SET_NULL, null=True)
    description = models.TextField(blank=True)
    scheduled_date = models.DateTimeField()
    status = models.ForeignKey(CounselingStatus, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    material_description = models.TextField(blank=True, null=True)
    material_files = models.ManyToManyField(Materials, related_name='counseling')

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['scheduled_date']
        db_table = 'counseling'

class CounselingResult(models.Model):
    consultation = models.ForeignKey(Counseling, on_delete=models.CASCADE)
    nurse = models.ForeignKey(Nurse, on_delete=models.SET_NULL, null=True)
    nurse_feedback = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    class Meta:
        db_table = 'counseling_result'
     
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
        
        