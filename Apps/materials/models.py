# from django.db import models
# from ..consultations.models import (
#     Consultation,
# )

# from ..accounts.models import (
#     Nurse,
#     User
# )

# # Create your models here.
# class Material(models.Model):
#     title = models.CharField(max_length=200)
#     description = models.TextField(blank=True)
#     content = models.TextField()
#     file = models.FileField(upload_to='materials/%Y/%m/', null=True, blank=True)
#     consultation = models.ForeignKey(Consultation, on_delete=models.CASCADE)
#     created_by = models.ForeignKey(User, on_delete=models.CASCADE)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#     is_required = models.BooleanField(default=True)
#     read_by = models.ManyToManyField(Nurse, through='MaterialReadStatus')

# class MaterialReadStatus(models.Model):
#     material = models.ForeignKey(Material, on_delete=models.CASCADE)
#     nurse = models.ForeignKey(Nurse, on_delete=models.CASCADE)
#     read_at = models.DateTimeField(auto_now_add=True)
#     understood = models.BooleanField(default=False)
#     feedback = models.TextField(blank=True)