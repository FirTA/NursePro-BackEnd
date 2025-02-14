# from django.db import models
# from ..accounts.models import (
#     Nurse,
#     User,
# )

# # Create your models here.
# class LevelCategory(models.Model):
#     code = models.CharField(max_length=10, unique=True)
#     name = models.CharField(max_length=100)
#     description = models.TextField(blank=True)
#     next_level = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL)
#     minimum_years = models.IntegerField(default=1)
#     created_at = models.DateTimeField(auto_now_add=True)

#     class Meta:
#         ordering = ['code']
#         verbose_name_plural = 'Level categories'

# class LevelUpgrade(models.Model):
#     STATUS_CHOICES = (
#         ('pending', 'Pending'),
#         ('approved', 'Approved'),
#         ('rejected', 'Rejected'),
#     )

#     nurse = models.ForeignKey(Nurse, on_delete=models.CASCADE)
#     from_level = models.ForeignKey(LevelCategory, related_name='upgrades_from', 
#                                  on_delete=models.PROTECT)
#     to_level = models.ForeignKey(LevelCategory, related_name='upgrades_to', 
#                                on_delete=models.PROTECT)
#     requested_at = models.DateTimeField(auto_now_add=True)
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
#     approved_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
#     approval_date = models.DateTimeField(null=True)
#     rejection_reason = models.TextField(blank=True)

#     class Meta:
#         ordering = ['-requested_at']