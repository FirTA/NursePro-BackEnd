from django.db.models.signals import post_delete,pre_delete,m2m_changed
from django.db.models import Count
from django.db import transaction
from django.dispatch import receiver
from core.models import (
    Materials,Counseling
)


@receiver(m2m_changed, sender=Counseling.material_files.through)
def handle_materials_change(sender, instance, action, pk_set, **kwargs):
    """Handle material deletions when removed from consultation"""
    if action == "pre_remove" and pk_set:
        Materials.objects.filter(id__in=pk_set).delete()


def delete_unused_materials(material_ids=None):
    query = Materials.objects.annotate(
        used_count=Count("counseling_materials")
    ).filter(used_count=0)
    
    if material_ids:
        query = query.filter(id__in=material_ids)
        
    # Log deletions for audit purposes
    deleted_count = query.count()
    if deleted_count:
        print(f"Deleting {deleted_count} unused materials")
    
    query.delete()