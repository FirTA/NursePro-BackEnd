# Generated by Django 5.1.4 on 2025-02-22 03:45

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0027_alter_materials_table'),
    ]

    operations = [
        migrations.AlterField(
            model_name='counselingmaterials',
            name='file',
            field=models.ManyToManyField(related_name='counseling_materials', to='core.materials'),
        ),
        migrations.RenameModel(
            old_name='ConsultationTypes',
            new_name='CounselingTypes',
        ),
        migrations.CreateModel(
            name='Counseling',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('scheduled_date', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('material_description', models.TextField(blank=True, null=True)),
                ('counseling_type', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='core.counselingtypes')),
                ('management', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='core.management')),
                ('material_files', models.ManyToManyField(related_name='counseling', to='core.materials')),
                ('nurses_id', models.ManyToManyField(to='core.nurse')),
                ('status', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='core.consultationstatus')),
            ],
            options={
                'db_table': 'counseling',
                'ordering': ['scheduled_date'],
            },
        ),
        migrations.AlterField(
            model_name='consultationresult',
            name='consultation',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.counseling'),
        ),
        migrations.AlterField(
            model_name='counselingmaterials',
            name='counseling',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='core.counseling'),
        ),
        migrations.DeleteModel(
            name='Consultations',
        ),
    ]
