# from django.db import models
# from django.contrib.auth.models import AbstractUser
# from django.core.validators import RegexValidator,MaxLengthValidator
# from django.core.exceptions import ValidationError
# from ..levels.models import LevelCategory


# # Create your models here.
# class User(AbstractUser):
#     ROLE_CHOICES = (
#         ('nurse', 'Nurse'),
#         ('management', 'Management'),
#         ('admin', 'Admin'),
#     )
        
#     def validate_length(value):
#         if len(value) > 20 :
#             raise ValidationError("Value exceeds maximum length of 20 characters.")  
    
#     email = models.EmailField(unique=True)
#     email_verified = models.BooleanField(default=False)
#     reset_password_token = models.CharField(max_length=100, blank=True, null=True)
#     reset_password_expire = models.DateTimeField(blank=True, null=True)
#     role = models.CharField(
#         max_length=50, 
#         choices=ROLE_CHOICES,
#         validators=[MaxLengthValidator(50)])
#     department = models.CharField(max_length=100)
#     account_id = models.CharField(
#         max_length=10, 
#         unique=True,
#         null=True,
#         validators=[MaxLengthValidator(10),RegexValidator(r'N\d{5}$','Nurse ID must be in format N12345')]
#         )
#     phone = models.CharField(
#         max_length=15, 
#         blank=True,
#         validators=[MaxLengthValidator(15)])
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)

#         # Add related_name to avoid clashes
#     groups = models.ManyToManyField(
#         'auth.Group',
#         related_name='custom_user_set',
#         blank=True,
#         verbose_name='groups',
#         help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
#     )
#     user_permissions = models.ManyToManyField(
#         'auth.Permission',
#         related_name='custom_user_set',
#         blank=True,
#         verbose_name='user permissions',
#         help_text='Specific permissions for this user.',
#     )
#     def __str__(self):
#         return self.username
  
#     class Meta:
#         indexes = [
#             models.Index(fields=['role','department']),
#             models.Index(fields=['account_id']),
#         ]

# class Nurse(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     current_level = models.ForeignKey(LevelCategory, on_delete=models.PROTECT)
#     level_updated_at = models.DateTimeField(auto_now=True)
#     years_of_service = models.IntegerField(default=0)
#     specialization = models.CharField(max_length=100, blank=True)
#     is_active = models.BooleanField(default=True)

#     class Meta:
#         ordering = ['user__account_id']