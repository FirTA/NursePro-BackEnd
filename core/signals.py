from django.db.models.signals import post_delete,pre_delete,m2m_changed
from django.db.models import Count
from django.db import transaction
from django.dispatch import receiver
from core.models import (
    CounselingMaterials,
    Materials,
)

@receiver(pre_delete, sender=CounselingMaterials)
def delete_related_materials(sender, instance, **kwargs):
    """
    Deletes all materials associated with the deleted CounselingMaterials instance
    if they are not linked to any other CounselingMaterials
    """
    
    related_files = instance.file.all()
    for material in related_files:
        material.delete()

@receiver(m2m_changed, sender=CounselingMaterials.file.through)
def auto_delete_materials(sender, instance, action, pk_set, **kwargs):
    if action == "post_remove":
        # Only check the specific materials that were removed
        transaction.on_commit(
            lambda: delete_unused_materials(pk_set)
        )

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