# Generated by Django 5.1.4 on 2025-02-18 07:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0019_remove_consultationmaterials_title_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='materials',
            name='size',
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
    ]
