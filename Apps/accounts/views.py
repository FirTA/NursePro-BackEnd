# from django.shortcuts import render

# # Create your views here.
# from rest_framework import viewsets, status, permissions
# from rest_framework.decorators import action
# from rest_framework.response import Response
# from .serializers import UserSerializer,NurseSerializer
# from .models import User,Nurse

# class NurseViewSet(viewsets.ModelViewSet):
#     serializer_class = NurseSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_queryset(self):
#         queryset = Nurse.objects.select_related('user', 'current_level')
#         if self.request.user.role == 'management':
#             return queryset.filter(user__department=self.request.user.department)
#         elif self.request.user.role == 'admin':
#             return queryset.all()
#         return queryset.filter(user=self.request.user)

#     @action(detail=True, methods=['post'])
#     def toggle_active(self, request, pk=None):
#         nurse = self.get_object()
#         nurse.is_active = not nurse.is_active
#         nurse.save()
#         return Response({'status': 'success'})