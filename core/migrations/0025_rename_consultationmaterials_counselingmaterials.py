# Generated by Django 5.1.4 on 2025-02-18 15:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0024_alter_consultationmaterials_table'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='ConsultationMaterials',
            new_name='CounselingMaterials',
        ),
    ]
