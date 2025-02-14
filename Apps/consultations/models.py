# from django.db import models
# from ..accounts.models import (
#     Nurse,
#     User,
# )

# # Create your models here.
# class Consultation(models.Model):
#     STATUS_CHOICES = (
#         ('scheduled', 'Scheduled'),
#         ('in_progress', 'In Progress'),
#         ('completed', 'Completed'),
#         ('cancelled', 'Cancelled'),
#     )
#     TYPE_CHOICES = (
#         ('regular', 'Regular'),
#         ('violation', 'Violation'),
#     )

#     nurse = models.ForeignKey(Nurse, on_delete=models.CASCADE)
#     management = models.ForeignKey(User, on_delete=models.CASCADE)
#     consultation_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
#     scheduled_date = models.DateTimeField()
#     completed_date = models.DateTimeField(null=True, blank=True)
#     notes = models.TextField(blank=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)

#     class Meta:
#         ordering = ['-scheduled_date']
#         indexes = [
#             models.Index(fields=['status', 'scheduled_date']),
#             models.Index(fields=['nurse', 'status']),
#         ]

# class ConsultationNote(models.Model):
#     consultation = models.ForeignKey(Consultation, related_name='notes_id', on_delete=models.CASCADE)
#     created_by = models.ForeignKey(User, on_delete=models.CASCADE)
#     content = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)
#     is_private = models.BooleanField(default=False)