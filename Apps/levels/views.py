# from datetime import timezone
# from django.shortcuts import render
# from rest_framework import permissions, viewsets ,views
# from rest_framework.decorators import action
# from rest_framework.response import Response

# from .models import (
#     LevelCategory,
#     LevelUpgrade,
# )

# from ..accounts.models import (
#     Nurse,
# )

# from .serializers import (
#     LevelUpgradeSerializer,
#     LevelCategorySerializer
# )

# # Create your views here.
# class LevelCategoryViewSet(viewsets.ModelViewSet):
#     queryset = LevelCategory.objects.all()
#     serializer_class = LevelCategorySerializer
#     permission_classes = [permissions.IsAdminUser]
    
# class AutoLevelUpgradeView(views.APIView):
#     permission_classes = [permissions.IsAdminUser]
    
#     def post(self,request):
#         nurses = Nurse.objects.all()
#         upgrades_created = 0
        
#         for nurse in nurses:
#             if self.is_eligible_for_upgrade(nurse):
#                 LevelUpgrade.objects.create(
#                     nurse = nurse,
#                     from_level = nurse.current_level,
#                     to_level = nurse.current_level.next_level,
#                     status = 'pending'
#                 )
#                 upgrades_created +=1
                
#         return Response({
#             'status' : 'success',
#             'upgrades_created' : upgrades_created
#         })
        
        
#     def is_eligible_for_upgrade(self,nurse):
#         current_level = nurse.current_level
#         if not current_level.next_level:
#             return False
        
#         years_in_current_level = (
#             timezone.now() - nurse.level_updated_at
#         ).days / 365.25
        
#         return years_in_current_level >= current_level.minimum_years
            
            