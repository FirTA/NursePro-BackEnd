from django.contrib import admin
from .models import LevelCategory

@admin.register(LevelCategory)
class LevelCategoryAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'next_level', 'minimum_years')
    search_fields = ('code', 'name')
    ordering = ('code',)