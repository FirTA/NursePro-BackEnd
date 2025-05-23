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
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
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
    current_level_start_date = models.DateField(null=True)

    def __str__(self):
        return self.nurse_account_id + " - " + self.user.first_name + " " + self.user.last_name

    def calculate_years_of_service(self):
        """Calculate years of service based on hire date."""
        if self.hire_date:
            today = timezone.now().date()
            difference = relativedelta(today, self.hire_date)
            # Convert to total months
            return (difference.years * 12) + difference.months
        return 0
    
    def should_upgrade_level(self):
        """Check if nurse should be upgraded based on time in current level."""
        if not (self.current_level and self.current_level_start_date):
            return False
            
        today = timezone.now().date()
        
        # If level_upgrade_date is set, use it as the target date
        if self.level_upgrade_date:
            return today >= self.level_upgrade_date
            
        # Otherwise calculate based on required time in current level
        time_in_level = relativedelta(today, self.current_level_start_date)
        months_in_level = (time_in_level.years * 12) + time_in_level.months
        
        return months_in_level >= self.current_level.required_time_in_month
    
    def get_eligible_level(self):
        """Determine the appropriate level based on years of service and current level."""
        years_of_service = self.calculate_years_of_service()
        
        # If nurse already has a level, get the next one if available
        if self.current_level:
            next_level = LevelReference.objects.filter(
                level=self.current_level.next_level
            ).first()
            
            if next_level:
                return next_level
        
        # If no current level or no next level defined, find appropriate level from scratch
        # This is useful for initial level assignment or corrections
        all_levels = LevelReference.objects.order_by('id')
        appropriate_level = None
        
        total_months = 0
        for level in all_levels:
            total_months += level.required_time_in_month
            if years_of_service < total_months:
                # If we haven't reached this level yet based on service time
                break
            appropriate_level = level
            
        return appropriate_level
    
    def update_level(self, manual=False, notes=None):
        """
        Update nurse's level if eligible.
        
        Args:
            manual: Whether this is a manual update (vs automatic)
            notes: Optional notes about the level change
            
        Returns:
            bool: True if level was updated, False if no update was needed/possible
        """
        # Get eligible level
        next_level = self.get_eligible_level()
        
        # If no eligible level or same as current, no update needed
        if not next_level or (self.current_level and next_level.id == self.current_level.id):
            return False
            
        # Determine status
        if manual:
            status = LevelUpgradeStatus.objects.get(status_name='Manual')
        else:
            status = LevelUpgradeStatus.objects.get(status_name='Automatic')
        
        # Create history record
        history = LevelHistory.objects.create(
            nurse=self,
            from_level=self.current_level,
            to_level=next_level,
            years_of_service=self.calculate_years_of_service(),
            status=status,
            notes=notes
        )
            
        # Update nurse record
        old_level = self.current_level
        self.current_level = next_level
        self.current_level_start_date = timezone.now().date()
        
        # Calculate new upgrade date
        self.level_upgrade_date = self.current_level_start_date + relativedelta(
            months=next_level.required_time_in_month
        )
        self.save(update_fields=[
            'current_level', 
            'current_level_start_date', 
            'level_upgrade_date',
            'update_at'
        ])
        
        return True
    
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
                status=LevelUpgradeStatus.objects.get(status_name='Automatic')
            )
            
            # Update to new level
            self.current_level = next_level
            
            # Set current level start date to today
            self.current_level_start_date = timezone.now().date()
            
            # Calculate new upgrade date
            self.level_upgrade_date = timezone.now().date() + relativedelta(months=next_level.required_time_in_month)
    
    def save(self, *args, **kwargs):
        # Calculate years of service
        self.years_of_service = self.calculate_years_of_service()
        
        is_new = not self.pk
        super().save(*args, **kwargs)
        
        # For new nurses, set initial level_upgrade_date if needed
        if is_new and self.current_level and self.current_level_start_date:
            required_months = self.current_level.required_time_in_month
            self.level_upgrade_date = self.current_level_start_date + relativedelta(months=required_months)
            super().save(update_fields=['level_upgrade_date'])

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
    notes = models.TextField(blank=True, null=True)

    
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
    file_path = models.FileField(upload_to="documents/")
    size = models.PositiveBigIntegerField(editable=True, null=True, blank=True)
    size_readable = models.CharField(max_length=20, editable=True, null=True, blank=True)  # human-readable size
    created_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        # Set the title if not provided
        if self.file_path and not self.title:
            self.title = os.path.basename(self.file_path.name)
        
        # Save the model first so the file is saved to storage
        super().save(*args, **kwargs)
        
        # Now get the file size from storage if possible
        if self.file_path and not self.size:
            try:
                # For Supabase, get the size of the uploaded file
                self.size = default_storage.size(self.file_path.name)
                self.size_readable = self._calculate_human_readable_size(self.size)
                # Update just these fields to avoid a loop
                super().save(update_fields=["size", "size_readable"])
            except Exception as e:
                print(f"Error getting file size: {e}")
    
    def delete(self, *args, **kwargs):
        """Delete file from storage when instance is deleted."""
        if self.file_path:
            try:
                # Delete the file through the storage backend
                default_storage.delete(self.file_path.name)
            except Exception as e:
                print(f"Error deleting file: {e}")
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
    counseling = models.ForeignKey(Counseling, on_delete=models.CASCADE)
    nurse = models.ForeignKey(Nurse, on_delete=models.SET_NULL, null=True)
    nurse_feedback = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    class Meta:
        db_table = 'counseling_result'
        
              
class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action_type = models.CharField(max_length=20, choices=[
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('VIEW', 'View'),
    ])
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')
    
    description = models.TextField(blank=True)
    data = models.JSONField(null=True, blank=True)  # Store changes as JSON
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
            models.Index(fields=['action_type']),
        ]
        db_table = 'auditlog'
        
    def __str__(self):
        return f"{self.action_type} by {self.user} on {self.content_type} #{self.object_id} at {self.timestamp}"

        
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
        
        