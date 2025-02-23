import base64
import jwt
import datetime

from rest_framework import viewsets
from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate
from django.utils import timezone
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import viewsets, status, permissions, views,generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken

from .serializers import (
    UserSerializer,
    NurseSerializer,
    UserCreateSerializer,
    UserRegistrationSerializers,
    ChangePasswordSerializer,
    ResetPasswordConfirmSerializer,
    ResetPasswordRequestSerializer,
    LoginSerializer,
    LogoutUserSerializer,
    DepartmentSerializer,
    LevelReferenceSerializer,
    LevelUpgradeStatusSerializer,
    LevelRequestUpdateSerializer,
    CounselingTypesSerializer,
    CounselingStatusSerializer,
    CounselingSerializer,
    ConsultationResultSerializer,
    CounselingMaterialSerializer,
    MaterialReadStatusSerializers,
    AuditLogSerializers,
    ManagementSerializers,
    SystemConfigurationSerializers,
    CounselingMaterialCreateSerializer,
    UserProfileSerializer,
)
from .models import (
    User,
    Nurse,
    Management,
    LevelReference,
    LevelUpgradeStatus,
    LevelUpgradeRequests,
    Department,
    Counseling,
    CounselingStatus,
    CounselingTypes,
    CounselingResult,
    CounselingMaterials,
    MaterialReadStatus,
    LevelHistory,
    SystemConfiguration,
    AuditLog,
    Materials
)
from rest_framework.decorators import api_view, permission_classes
from django.utils.decorators import method_decorator
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from rest_framework.request import Request
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_simplejwt.tokens import RefreshToken

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    try:
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=500)
        
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_profile_page(request):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_profile_picture(request):
    if 'profile_picture' not in request.FILES:
        return Response({'error': 'No image provided'}, status=400)
    
    user = request.user
    user.profile_picture = request.FILES['profile_picture'].read()
    user.save()
    
    serializer = UserProfileSerializer(user)
    return Response(serializer.data)

class CustomTokenRefresh(TokenRefreshView):
  def post(self, request, *args, **kwargs):
        try:
            # Call the original TokenRefreshView logic
            print(request)
            response = super().post(request, *args, **kwargs)

            # If successful, return the response as usual
            if response.status_code == 200:
                return response
        except Exception as e:
            refresh = request.data.get("refresh")
            print(e)
            print(refresh)
            token = RefreshToken(refresh)
            user_id = token.payload.get('user_id')
            user = User.objects.get(id = user_id)
            user.is_login = False
            user.save()
            return Response(
                {"error": "Refresh token expired. Please log in again."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

class TokenIdentifyView(APIView):
    def post(self, request):
        # Extract the token from the request
        token = request.data.get('token')
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            access_token = AccessToken(token)
            claims = access_token.payload
            username = claims.get('username')
            role = claims.get('role')
            
            
            new_token = AccessToken.for_user(request.user)
            new_token['username'] = username
            new_token['role'] = role
            
            response_data = {
                'username' : username,
                'role' : role,
                'access_token' : str(new_token),
            }
            return Response(response_data, status=status.HTTP_200_OK)            
        except (InvalidToken, TokenError) as e:
            return Response({"error": "Token is not valid"}, status=status.HTTP_401_UNAUTHORIZED)            

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'status': 'success',
                'message': 'User registered successfully',
                'user_id': user.id
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(GenericAPIView):
    permission_classes = [AllowAny]  # Allow access without authentication
    serializer_class=LoginSerializer
    
    def post(self, request):
        serializer= self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        print(serializer.validated_data)
        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        return response


class LogoutApiView(GenericAPIView):
    serializer_class=LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print('post logout')
        
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            decoded_token = AccessToken(token)
            user = User.objects.get(id = decoded_token.payload['user_id'])
            print(f'-- {user.username} is logout --> false')
            user.is_login = False
            user.save()
        
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    
class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.data.get('old_password')):
            return Response(
                {'old_password': 'Wrong password.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(serializer.data.get('new_password'))
        user.save()
        return Response({'detail': 'Password successfully changed.'})

class RequestPasswordResetView(generics.GenericAPIView):
    serializer_class = ResetPasswordRequestSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = User.objects.get(email=serializer.data['email'])
            token = str(uuid.uuid4())
            user.reset_password_token = token
            user.reset_password_expire = timezone.now() + timedelta(hours=24)
            user.save()

            reset_url = f"{settings.FRONTEND_URL}/reset-password/{token}"
            send_mail(
                'Password Reset Request',
                f'Click the following link to reset your password: {reset_url}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({'detail': 'Password reset email has been sent.'})
        except User.DoesNotExist:
            return Response({'detail': 'User with this email does not exist.'})

class ResetPasswordConfirmView(generics.GenericAPIView):
    serializer_class = ResetPasswordConfirmSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = User.objects.get(
                reset_password_token=serializer.data['token'],
                reset_password_expire__gt=timezone.now()
            )
            user.set_password(serializer.data['new_password'])
            user.reset_password_token = None
            user.reset_password_expire = None
            user.save()
            return Response({'detail': 'Password has been reset.'})
        except User.DoesNotExist:
            return Response(
                {'detail': 'Invalid or expired token.'},
                status=status.HTTP_400_BAD_REQUEST
            )

class NurseViewSet(viewsets.ModelViewSet):
    serializer_class = NurseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = Nurse.objects.select_related('user', 'current_level')
        if self.request.user.role.name == 'Management':
            return queryset.all()
        elif self.request.user.role.name == 'admin' :
            return queryset.all()
        
        return queryset.filter(user=self.request.user)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        nurse = self.get_object()
        nurse.is_active = not nurse.is_active
        nurse.save()
        return Response({'status': 'success'})
    
class NurseLevelView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        if request.user.role.role_name != 'Nurse':
            
            return Response({'error' : 'Only nurses can view their current level'},status=status.HTTP_403_FORBIDDEN)

        nurse = request.user.nurse
        level_id = LevelReference.objects.get(level = nurse.current_level)
        serializer = LevelReferenceSerializer(level_id)
        print(serializer.data['next_level'])
        return Response(serializer.data['next_level'],status=status.HTTP_200_OK)


class CounselingViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Counseling.objects.all()
    serializer_class = CounselingSerializer
    
    def perform_create(self, serializer):
        serializer.save(management=self.request.user.management)

    @action(detail=True, methods=['post'])
    def remove_file(self, request, pk=None):
        counseling = self.get_object()
        file_id = request.data.get('file_id')
        
        try:
            material = counseling.material_files.get(id=file_id)
            counseling.material_files.remove(material)
            # Signal will handle the file deletion
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Materials.DoesNotExist:
            return Response(
                {"detail": "File not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
            
class ConsultationResultViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = CounselingResult.objects.all()
    serializer_class = ConsultationResultSerializer
            
class CounselingMaterialsViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = CounselingMaterials.objects.all()
    serializer_class = CounselingMaterialSerializer
    
    def get_serializer_class(self):
        
        if self.request.method == "PATCH":
            return CounselingMaterialCreateSerializer
        return super().get_serializer_class()
            
class MaterialReadStatusViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = MaterialReadStatus.objects.all()
    serializer_class = MaterialReadStatusSerializers
            
class MaterialReadStatusViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = MaterialReadStatus.objects.all()
    serializer_class = MaterialReadStatusSerializers
                                 
class AuditLogViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializers
            
class SystemConfigurationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = SystemConfiguration.objects.all()
    serializer_class = SystemConfigurationSerializers

class ManagementViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Management.objects.all()
    serializer_class = ManagementSerializers
            
         
         
         
class TestAuthView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]  
    
    def get(self, request):
        # token = "your_access_token"
        
        print(request.user.role.role_name)
        if request.user.role.role_name != 'Nurse':
            return Response({'error' : 'Only nurses can view their current level'},status=status.HTTP_403_FORBIDDEN)

        # print(request.data)
        decoded_token = AccessToken(request.data['access_token'])
        user_id = decoded_token.payload['user_id']
        # print(decoded_token.payload)
        nurse_id = Nurse.objects.get(user_id = user_id)
        print(f"user_id : {nurse_id} ")
        consultation_list = Counseling.objects.filter(nurses_id = nurse_id)
        
        for consultation_item in consultation_list:
            print(f"{consultation_item} - {consultation_item.management}")
        data = {
            'msg' : 'its workds',
            # 'tokem' : decoded_token
        }
        # print(decoded_token)  # Example of getting user ID from the token
        
        return Response(status=status.HTTP_200_OK)

class LevelReferenceViewSet(viewsets.ModelViewSet):
    queryset = LevelReference.objects.all()
    serializer_class = LevelReferenceSerializer
    permission_classes = [IsAuthenticated]
    
class LevelUpgradeStatusViewSet(viewsets.ModelViewSet):
    queryset = LevelUpgradeStatus.objects.all()
    serializer_class = LevelUpgradeStatusSerializer
    permission_classes = [IsAuthenticated]
    
class DepartmentViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated]
    
class ConsultationStatusViewSet(viewsets.ModelViewSet):
    queryset = CounselingStatus.objects.all()
    serializer_class = CounselingStatusSerializer
    permission_classes = [IsAuthenticated]
    
class ConsultationTypesViewSet(viewsets.ModelViewSet):
    queryset = CounselingTypes.objects.all()
    serializer_class = CounselingTypesSerializer
    permission_classes = [IsAuthenticated]   
# # Create your views here.
# class ConsultationViewSet(viewsets.ModelViewSet):
#     serializer_class = ConsultationSerializers
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         if self.request.user.role == 'nurse':
#             return Consultation.objects.filter(nurses__user = self.request.user)
#         return Consultation.objects.filter(management = self.request.user)

#     def perform_create(self, serializer):
#         nurses = self.request.data.get('nurses')  # Expecting a list of nurse IDs
#         consultation = serializer.save(management=self.request.user)
#         if nurses:
#             consultation.nurses.set(nurses)  # Associate multiple nurses with the consultation
        

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