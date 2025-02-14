# from django.urls import path, include
# from rest_framework.routers import DefaultRouter
# from .views import (
#     LevelCategoryViewSet,
#     AutoLevelUpgradeView
#     )

# router = DefaultRouter()
# router.register(r'levels', LevelCategoryViewSet, basename='level')
# # ... other router registrations ...

# urlpatterns = [
#     path('', include(router.urls)),
#     path('auto-upgrade/', AutoLevelUpgradeView.as_view(), name='auto-upgrade'),
# ]