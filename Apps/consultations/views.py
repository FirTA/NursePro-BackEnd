# from django.shortcuts import render
# from rest_framework import viewsets, permissions
# from rest_framework.decorators import action
# from rest_framework.response import Response
# from .serializers import (
#     ConsultationNote,
#     Consultation,
#     )



# # Create your views here.
# class ConsultationViewSet(viewsets.ModelViewSet):
#     serializer_class = Consultation
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         if self.request.user.role == 'nurse':
#             return Consultation.objects.filter(nurse__user = self.request.user)
#         return Consultation.objects.filter(management = self.request.user)

#     def perform_create(self, serializers):
#         serializers.save(management = self.request.user)
        
