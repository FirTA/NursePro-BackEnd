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
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, permissions, filters, status
from django.db.models import Q
from django.db.models import Count, Prefetch


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
    CounselingTypesSerializer,
    CounselingStatusSerializer,
    CounselingSerializer,
    CounselingResultSerializer,
    AuditLogSerializers,
    ManagementSerializers,
    SystemConfigurationSerializers,
    UserProfileSerializer,
)
from .models import (
    User,
    Nurse,
    Management,
    LevelReference,
    LevelUpgradeStatus,
    Department,
    Counseling,
    CounselingStatus,
    CounselingTypes,
    CounselingResult,
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
from dateutil.relativedelta import relativedelta
import calendar
from datetime import datetime, timedelta


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def management_dashboard(request):
    """
    Dashboard data for management users
    """
    # Check if user is management or admin
    user_role = request.user.role.name.lower() if request.user.role else ''
    if user_role not in ['management', 'admin']:
        return Response(
            {"error": "Only management users can access this endpoint"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Get all counseling sessions
    all_counseling = Counseling.objects.all()
    
    # Get completed sessions (status 3 is assumed to be "Completed")
    completed_status = CounselingStatus.objects.get(id=3)
    completed_counseling = all_counseling.filter(status=completed_status)
    
    # Get scheduled sessions (future sessions)
    today = timezone.now()
    scheduled_counseling = all_counseling.filter(
        scheduled_date__gt=today,
        status__id__in=[1, 2]  # Assuming 1=Scheduled, 2=In Progress
    )
    
    # Get recent completed sessions
    recent_completed = completed_counseling.order_by('-scheduled_date')[:5]
    
    # Get upcoming sessions
    upcoming_sessions = scheduled_counseling.order_by('scheduled_date')[:5]
    
    # Get total nurse count
    nurse_count = Nurse.objects.filter(is_active=True).count()
    
    # Get nurse count by level
    nurse_by_level = Nurse.objects.filter(is_active=True).values(
        'current_level__level'
    ).annotate(count=Count('id'))
    
    # Get pending notes count (completed sessions without notes from all nurses)
    sessions_with_notes = CounselingResult.objects.values('consultation').distinct()
    completed_without_notes = completed_counseling.exclude(
        id__in=[item['consultation'] for item in sessions_with_notes]
    ).count()
    
    # Get completed sessions with partial notes
    sessions_with_partial_notes = []
    for session in completed_counseling:
        nurses_count = session.nurses_id.count()
        notes_count = CounselingResult.objects.filter(consultation=session).count()
        if 0 < notes_count < nurses_count:
            sessions_with_partial_notes.append(session.id)
    
    pending_notes_count = completed_without_notes + len(sessions_with_partial_notes)
    
    # Get counseling sessions by month (last 6 months)
    months_data = []
    for i in range(5, -1, -1):
        month_start = (today - relativedelta(months=i)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_end = (month_start + relativedelta(months=1)) - timedelta(seconds=1)
        
        month_name = calendar.month_name[month_start.month][:3] + " " + str(month_start.year)
        
        completed_count = completed_counseling.filter(
            scheduled_date__gte=month_start,
            scheduled_date__lte=month_end
        ).count()
        
        scheduled_count = scheduled_counseling.filter(
            scheduled_date__gte=month_start,
            scheduled_date__lte=month_end
        ).count()
        
        months_data.append({
            'month': month_name,
            'completed': completed_count,
            'scheduled': scheduled_count
        })
    
    # Get counseling by type
    counseling_by_type = []
    for ctype in CounselingTypes.objects.all():
        count = all_counseling.filter(counseling_type=ctype).count()
        if count > 0:
            counseling_by_type.append({
                'name': ctype.name,
                'value': count
            })
    
    # Build response data
    response_data = {
        'counselingStats': {
            'total': all_counseling.count(),
            'completed': completed_counseling.count(),
            'scheduled': scheduled_counseling.count(),
            'pendingNotes': pending_notes_count
        },
        'nurseStats': {
            'total': nurse_count,
            'byLevel': [{'level': item['current_level__level'], 'count': item['count']} for item in nurse_by_level]
        },
        'recentCounseling': [],
        'upcomingCounseling': [],
        'counselingByMonth': months_data,
        'counselingByType': counseling_by_type
    }
    
    # Process and add recent completed sessions
    for counseling in recent_completed:
        nurses_count = counseling.nurses_id.count()
        notes_count = CounselingResult.objects.filter(consultation=counseling).count()
        
        response_data['recentCounseling'].append({
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'notes_count': notes_count,
            'nurses': [
                {
                    'id': nurse.id,
                    'name': f"{nurse.user.first_name} {nurse.user.last_name}",
                } for nurse in counseling.nurses_id.all()
            ],
        })
    
    # Process and add upcoming sessions
    for counseling in upcoming_sessions:
        response_data['upcomingCounseling'].append({
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'type': counseling.counseling_type.name if counseling.counseling_type else "General",
            'nurses': [
                {
                    'id': nurse.id,
                    'name': f"{nurse.user.first_name} {nurse.user.last_name}",
                } for nurse in counseling.nurses_id.all()
            ],
        })
    
    return Response(response_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def nurse_dashboard(request):
    """
    Dashboard data for nurse users
    """
    # Check if user is a nurse
    user_role = request.user.role.name.lower() if request.user.role else ''
    if user_role != 'nurse':
        return Response(
            {"error": "Only nurse users can access this endpoint"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Get the nurse object
    try:
        nurse = Nurse.objects.get(user=request.user)
    except Nurse.DoesNotExist:
        return Response(
            {"error": "Nurse profile not found"},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get current date
    today = timezone.now()
    
    # Get all counseling sessions for this nurse
    nurse_counseling = Counseling.objects.filter(nurses_id=nurse)
    
    # Get completed sessions 
    completed_status = CounselingStatus.objects.get(id=3)
    completed_counseling = nurse_counseling.filter(status=completed_status)
    
    # Get upcoming sessions
    upcoming_counseling = nurse_counseling.filter(
        scheduled_date__gt=today,
        status__id__in=[1, 2]  # Assuming 1=Scheduled, 2=In Progress
    ).order_by('scheduled_date')[:5]
    
    # Get sessions needing notes
    # First, get all completed counseling IDs
    completed_ids = list(completed_counseling.values_list('id', flat=True))
    
    # Then, get all counseling IDs that already have notes from this nurse
    notes_submitted_ids = list(CounselingResult.objects.filter(
        consultation__in=completed_ids,
        nurse=nurse
    ).values_list('consultation_id', flat=True))
    
    # Find sessions needing notes (completed but no notes submitted)
    sessions_needing_notes = completed_counseling.exclude(
        id__in=notes_submitted_ids
    ).order_by('-scheduled_date')[:5]
    
    # Get recent completed sessions with notes
    recent_completed_with_notes = []
    for counseling in completed_counseling.order_by('-scheduled_date')[:5]:
        note = CounselingResult.objects.filter(consultation=counseling, nurse=nurse).first()
        has_notes = note is not None
        
        recent_completed_with_notes.append({
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'type': counseling.counseling_type.name if counseling.counseling_type else "General",
            'hasNotes': has_notes,
            'noteId': note.id if note else None,
            'noteContent': note.nurse_feedback if note else None
        })
    
    # Calculate level progress and next level date
    level_progress = 0
    next_level_date = None
    
    if nurse.level_upgrade_date and nurse.current_level:
        hire_date = nurse.hire_date
        current_date = today.date()
        next_level_date = nurse.level_upgrade_date
        
        # Calculate progress as percentage of time elapsed since hire
        if hire_date and next_level_date:
            total_days = (next_level_date - hire_date).days
            elapsed_days = (current_date - hire_date).days
            
            if total_days > 0:
                level_progress = min(100, round((elapsed_days / total_days) * 100))
    
    # Build response data
    response_data = {
        'nurseInfo': {
            'name': f"{nurse.user.first_name} {nurse.user.last_name}",
            'level': nurse.current_level.level if nurse.current_level else "Unspecified",
            'levelProgress': level_progress,
            'nextLevelDate': next_level_date,
            'yearsOfService': nurse.years_of_service,
            'department': nurse.department.name if nurse.department else "Unspecified",
            'specialization': nurse.specialization
        },
        'counselingSessions': {
            'upcoming': [],
            'completed': recent_completed_with_notes,
            'needNotes': []
        },
        'stats': {
            'totalSessions': nurse_counseling.count(),
            'completedSessions': completed_counseling.count(),
            'pendingNotes': sessions_needing_notes.count()
        }
    }
    
    # Process and add upcoming sessions
    for counseling in upcoming_counseling:
        response_data['counselingSessions']['upcoming'].append({
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'type': counseling.counseling_type.name if counseling.counseling_type else "General"
        })
    
    # Process and add sessions needing notes
    for counseling in sessions_needing_notes:
        response_data['counselingSessions']['needNotes'].append({
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'type': counseling.counseling_type.name if counseling.counseling_type else "General"
        })
    
    return Response(response_data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_counseling_completed(request, counseling_id):
    """
    Mark a counseling session as completed.
    Only management or admin users can mark a session as completed.
    The session can only be marked as completed if the scheduled time has passed.
    """
    # Check if user is management or admin
    user_role = request.user.role.name.lower() if request.user.role else ''
    if user_role not in ['management', 'admin']:
        return Response(
            {"error": "Only management or admin users can mark sessions as completed"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        counseling = Counseling.objects.get(pk=counseling_id)
        
        # Check if scheduled time has passed
        if counseling.scheduled_date and counseling.scheduled_date > timezone.now():
            return Response(
                {"error": "Cannot mark as completed before the scheduled time"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update status to completed (assuming 3 is the "completed" status code)
        counseling.status_id = 3
        counseling.save()
        
        serializer = CounselingSerializer(counseling)
        return Response(serializer.data)
    
    except Counseling.DoesNotExist:
        return Response(
            {"error": "Counseling session not found"},
            status=status.HTTP_404_NOT_FOUND
        )


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
            
class CounselingResultViewSet(viewsets.ModelViewSet):
    """
    ViewSet for CounselingResult model (Session Notes)
    """
    serializer_class = CounselingResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['nurse_feedback', 'consultation__title', 'nurse__name']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']  # Default order is newest first

    def get_queryset(self):
        """
        Filter queryset based on user role:
        - Nurses can only see their own notes
        - Management can see all notes
        """
        user = self.request.user
        if not hasattr(user, 'role'):
            return CounselingResult.objects.none()

        role = user.role.name.lower() if user.role else ''
        
        if role in ['management', 'admin']:
            # Management/admin can see all notes
            queryset = CounselingResult.objects.all()
        elif role == 'nurse':
            # Nurses can only see their own notes
            try:
                nurse = Nurse.objects.get(user=user)
                queryset = CounselingResult.objects.filter(nurse=nurse)
            except Nurse.DoesNotExist:
                return CounselingResult.objects.none()
        else:
            return CounselingResult.objects.none()
        
        # Manual filtering
        consultation = self.request.query_params.get('consultation', None)
        if consultation:
            queryset = queryset.filter(consultation_id=consultation)
            
        nurse = self.request.query_params.get('nurse', None)
        if nurse:
            queryset = queryset.filter(nurse_id=nurse)
        
        # Search filtering
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(nurse_feedback__icontains=search) |
                Q(consultation__title__icontains=search) |
                Q(nurse__name__icontains=search)
            )
        
        return queryset

    @action(detail=False, methods=['get'], url_path=r'(?P<counseling_id>\d+)/nurse/(?P<nurse_id>\d+)')
    def get_note_by_counseling_and_nurse(self, request, counseling_id=None, nurse_id=None):
        """
        Get a specific note for a counseling session from a specific nurse
        """
        try:
            counseling = get_object_or_404(Counseling, pk=counseling_id)
            nurse = get_object_or_404(Nurse, pk=nurse_id)
            
            # Check permissions - nurses should only be able to access their own notes
            if request.user.role.name.lower() == 'nurse':
                try:
                    user_nurse = Nurse.objects.get(user=request.user)
                    if str(user_nurse.id) != nurse_id:
                        return Response(
                            {"error": "You can only access your own notes"},
                            status=status.HTTP_403_FORBIDDEN
                        )
                except Nurse.DoesNotExist:
                    return Response(
                        {"error": "Nurse profile not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            note = get_object_or_404(CounselingResult, consultation=counseling, nurse=nurse)
            serializer = self.get_serializer(note)
            return Response(serializer.data)
        except CounselingResult.DoesNotExist:
            return Response(
                {"error": "No note found for this counseling session and nurse"},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['get'], url_path='by-counseling')
    def notes_by_counseling(self, request):
        """
        Get all counseling sessions with their associated notes.
        Only accessible to management users.
        """
        # Check if user is management or admin
        user_role = request.user.role.name.lower() if request.user.role else ''
        if user_role not in ['management', 'admin']:
            return Response(
                {"error": "Only management or admin users can access this endpoint"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get query parameters
        search = request.query_params.get('search', '')
        
        # Get counseling sessions with notes count
        counseling_with_notes = Counseling.objects.filter(
            status__id=3  # Only completed sessions
        ).annotate(
            notes_count=Count('counselingresult')
        ).filter(
            notes_count__gt=0  # Only sessions with at least one note
        )
        
        # Apply search if provided
        if search:
            counseling_with_notes = counseling_with_notes.filter(
                Q(title__icontains=search) |
                Q(nurses_id__user__first_name__icontains=search) |
                Q(nurses_id__user__last_name__icontains=search) |
                Q(counselingresult__nurse_feedback__icontains=search)
            ).distinct()
        
        # Prefetch related notes with their nurses to avoid N+1 queries
        counseling_with_notes = counseling_with_notes.prefetch_related(
            Prefetch(
                'counselingresult_set',
                queryset=CounselingResult.objects.select_related('nurse__user')
            ),
            'nurses_id__user',
            'status',
            'counseling_type',
            'management'
        )
        
        # Serialize the data
        result = []
        for counseling in counseling_with_notes:
            notes = []
            for note in counseling.counselingresult_set.all():
                notes.append({
                    'id': note.id,
                    'nurse': {
                        'id': note.nurse.id if note.nurse else None,
                        'name': f"{note.nurse.user.first_name} {note.nurse.user.last_name}" if note.nurse and note.nurse.user else 'Unknown',
                        'level': note.nurse.current_level.level if note.nurse and note.nurse.current_level else None,
                        'department': note.nurse.department.name if note.nurse and note.nurse.department else None
                    },
                    'nurse_feedback': note.nurse_feedback,
                    'created_at': note.created_at,
                    'updated_at': note.updated_at
                })
                
            result.append({
                'id': counseling.id,
                'title': counseling.title,
                'scheduled_date': counseling.scheduled_date,
                'status': {
                    'id': counseling.status.id if counseling.status else None,
                    'name': counseling.status.name if counseling.status else 'Unknown'
                },
                'counseling_type': {
                    'id': counseling.counseling_type.id if counseling.counseling_type else None,
                    'name': counseling.counseling_type.name if counseling.counseling_type else 'Unknown'
                },
                'management': {
                    'id': counseling.management.id if counseling.management else None,
                    'name': f"{counseling.management.user.first_name} {counseling.management.user.last_name}" if counseling.management and counseling.management.user else 'Unknown',
                    'position': counseling.management.position if counseling.management else None
                },
                'description': counseling.description,
                'nurses': [
                    {
                        'id': nurse.id,
                        'name': f"{nurse.user.first_name} {nurse.user.last_name}" if nurse.user else "Unknown",
                        'level': nurse.current_level.level if nurse.current_level else None,
                        'department': nurse.department.name if nurse.department else None
                    } for nurse in counseling.nurses_id.all()
                ],
                'notes': notes,
                'notes_count': len(notes)
            })
        
        return Response(result)
                            
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