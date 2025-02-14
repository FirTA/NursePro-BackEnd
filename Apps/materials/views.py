# from django.shortcuts import render
# from rest_framework import viewsets, permissions
# from rest_framework.decorators import action
# from rest_framework.response import Response
# from .serializers import (
#     MaterialSerializers,
#     MaterialReadStatusSerializers,
#     )
# from .models import (
#     Material,
#     MaterialReadStatus,
# )
# from ..consultations.models import (
#     Consultation,
#     )

# # Create your views here.
# class MaterialViewSet(viewsets.ModelViewSet):
#     serializer_class = MaterialSerializers
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         return Material.objects.filter(
#             consultation__in = Consultation.objects.filter(
#                 nurse__user = self.request.user
#             )
#             if self.request.user.role == 'nurse'
#             else Consultation.objects.all()            
#         )

#     def perform_create(self, serializer):
#         serializer.save(created_by=self.request.user)    