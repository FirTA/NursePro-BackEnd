# Generated by Django 5.1.4 on 2025-02-26 16:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0040_alter_materials_file_path'),
    ]

    operations = [
        migrations.RenameField(
            model_name='counselingresult',
            old_name='consultation',
            new_name='counseling',
        ),
    ]
