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
from .mixins import DatabaseRetryMixin
from django.db.models.functions import Concat
from django.db.models import Value, CharField

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
    UserProfileSerializer,RoleSerializer,AdminUserSerializer,NurseSimpleSerializer
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
    Materials,
    LoginHistory,
    Roles
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
from django.contrib.auth.hashers import make_password
from django.views.decorators.cache import cache_page
from django.core.cache import cache

def invalidate_dashboard_caches():
    """
    Invalidate all dashboard-related caches in a way compatible with all cache backends
    """
    # Clear specific cache keys that we know are used
    cache_prefixes = ['management_dashboard_', 'nurse_dashboard_', 'admin_dashboard_']
    
    # If we have user IDs, we can be more specific
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    # Try to get a limited set of user IDs to avoid excessive DB queries
    user_ids = list(User.objects.values_list('id', flat=True)[:100])
    
    # Invalidate each specific cache key
    for prefix in cache_prefixes:
        # Clear the generic keys first
        cache.delete(f"{prefix}all")
        
        # Then clear user-specific keys
        for user_id in user_ids:
            cache.delete(f"{prefix}{user_id}")



@api_view(['GET'])
@permission_classes([IsAuthenticated])
@cache_page(60 * 5)
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
    
    
    cache_key = f"management_dashboard_{request.user.id}"
    cached_data = cache.get(cache_key)
    if cached_data:
        return Response(cached_data)
    
    # Get all counseling sessions
    all_counseling = Counseling.objects.select_related(
        'status', 'counseling_type'
        ).prefetch_related('nurses_id__user')
        
    COMPLETED_STATUS_ID = 3
    completed_status = CounselingStatus.objects.get(id=COMPLETED_STATUS_ID)
        
    completed_counseling = all_counseling.filter(status=completed_status)
    
    # Get scheduled sessions (future sessions)
    today = timezone.now()
    scheduled_counseling = all_counseling.filter(
        scheduled_date__gt=today,
        status__id__in=[1, 2] 
    )
    
    # Get recent completed sessions
    recent_completed = completed_counseling.order_by('-scheduled_date')[:5]
    
    # Get upcoming sessions
    upcoming_sessions = scheduled_counseling.order_by('scheduled_date')[:5]
    
    nurse_stats = Nurse.objects.filter(is_active = True).aggregate(
        total_count=Count('id'),
        level_stats=Count('current_level',distinct=True)
    )
    
    nurse_count = nurse_stats['total_count']
    
    # Get nurse count by level
    nurse_by_level = Nurse.objects.filter(is_active=True).values(
        'current_level__level'
    ).annotate(count=Count('id')).order_by('current_level__level')
    
    completed_ids = list(completed_counseling.values_list('id',flat=True))
    
    sessions_with_notes_count = CounselingResult.objects.filter(
        counseling__in = completed_ids
        ).values('counseling').annotate(
            notes_count=Count('id'),
            nurse_count=Count('counseling__nurses_id',distinct=True)
        )
    
    pending_notes_count = 0
    for session in sessions_with_notes_count:
        if session['notes_count'] == 0:
            pending_notes_count += 1
        elif session['notes_count'] < session['nurse_count']:
            pending_notes_count += 1
    
    six_months_ago = today - relativedelta(months=5)
    six_months_ago = six_months_ago.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Get all counseling in the past 6 months with a single query
    counseling_by_month = all_counseling.filter(
        scheduled_date__gte=six_months_ago
    ).extra({
        'month': "to_char(scheduled_date, 'Mon YYYY')"
    }).values('month', 'status__id').annotate(count=Count('id')).order_by('month')
    
    # Process the result for the response
    months_data = []
    month_data_map = {}
    
    for i in range(5, -1, -1):
        month_date = (today - relativedelta(months=i)).replace(day=1)
        month_name = calendar.month_name[month_date.month][:3] + " " + str(month_date.year)
        month_data_map[month_name] = {'month': month_name, 'completed': 0, 'scheduled': 0}
        months_data.append(month_data_map[month_name])
    
    for item in counseling_by_month:
        month = item['month']
        if month in month_data_map:
            if item['status__id'] == COMPLETED_STATUS_ID:
                month_data_map[month]['completed'] = item['count']
            elif item['status__id'] in [1, 2]:  # Scheduled or In Progress
                month_data_map[month]['scheduled'] = item['count']
    
    # Get counseling by type in a single query
    counseling_by_type_data = all_counseling.values(
        'counseling_type__name'
    ).annotate(
        value=Count('id')
    ).filter(value__gt=0).order_by('-value')
    
    counseling_by_type = [
        {
            'name': item['counseling_type__name'] or 'Unspecified',
            'value': item['value']
        } for item in counseling_by_type_data
    ]
    
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
    
    # Optimize: Use a more efficient query to get notes count
    recent_completed_ids = [c.id for c in recent_completed]
    notes_counts = dict(CounselingResult.objects.filter(
        counseling__in=recent_completed_ids
    ).values('counseling').annotate(count=Count('id')).values_list('counseling', 'count'))
    
    for counseling in recent_completed:
        notes_count = notes_counts.get(counseling.id, 0)
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
    
    # Cache the response data
    cache.set(cache_key, response_data, 60 * 5)  # 5 minutes
    
    return Response(response_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def nurse_dashboard(request):
    """
    Dashboard data for nurse users with improved performance
    """
    # Check if user is a nurse
    user_role = request.user.role.name.lower() if request.user.role else ''
    if user_role != 'nurse':
        return Response(
            {"error": "Only nurse users can access this endpoint"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Use cache for faster repeat access
    cache_key = f"nurse_dashboard_{request.user.id}"
    cached_data = cache.get(cache_key)
    if cached_data:
        return Response(cached_data)
    
    # Get the nurse object
    try:
        # Use select_related to get user and department in one query
        nurse = Nurse.objects.select_related(
            'user', 'department', 'current_level'
        ).get(user=request.user)
    except Nurse.DoesNotExist:
        return Response(
            {"error": "Nurse profile not found"},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get current date
    today = timezone.now()
    
    # Use one optimized query for all counseling sessions
    # Get all counseling sessions for this nurse with related data
    nurse_counseling = Counseling.objects.filter(
        nurses_id=nurse
    ).select_related(
        'status', 'counseling_type'
    )
    
    # Get completed sessions 
    COMPLETED_STATUS_ID = 3
    completed_counseling = nurse_counseling.filter(status__id=COMPLETED_STATUS_ID)
    
    # Get upcoming sessions
    upcoming_counseling = nurse_counseling.filter(
        scheduled_date__gt=today,
        status__id__in=[1, 2]  # Assuming 1=Scheduled, 2=In Progress
    ).order_by('scheduled_date')[:5]
    
    # Use a more efficient query to find completed sessions needing notes
    # Get all completed IDs
    completed_ids = list(completed_counseling.values_list('id', flat=True))
    
    # Get IDs of sessions that already have notes from this nurse
    notes_submitted_ids = list(CounselingResult.objects.filter(
        counseling__in=completed_ids,
        nurse=nurse
    ).values_list('counseling_id', flat=True))
    
    # Find sessions needing notes
    sessions_needing_notes = completed_counseling.exclude(
        id__in=notes_submitted_ids
    ).order_by('-scheduled_date')[:5]
    
    # Get recent completed sessions with notes in a more efficient way
    recent_completed = completed_counseling.order_by('-scheduled_date')[:5]
    recent_completed_ids = [c.id for c in recent_completed]
    
    # Get all notes for the recent completed sessions in a single query
    notes_dict = {}
    for note in CounselingResult.objects.filter(
        counseling__in=recent_completed_ids,
        nurse=nurse
    ):
        notes_dict[note.counseling_id] = {
            'id': note.id,
            'content': note.nurse_feedback
        }
    
    # Build completed sessions data with the notes information
    recent_completed_with_notes = []
    for counseling in recent_completed:
        note_info = notes_dict.get(counseling.id, None)
        has_notes = note_info is not None
        
        recent_completed_with_notes.append({
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'type': counseling.counseling_type.name if counseling.counseling_type else "General",
            'hasNotes': has_notes,
            'noteId': note_info['id'] if note_info else None,
            'noteContent': note_info['content'] if note_info else None
        })
    
    # Calculate level progress more efficiently
    level_progress = 0
    next_level_date = None

    if nurse.level_upgrade_date and nurse.current_level:
        current_date = today.date()
        next_level_date = nurse.level_upgrade_date
        
        # Use the specific start date for this level
        level_start_date = nurse.current_level_start_date or nurse.hire_date
        
        # Calculate progress based on elapsed time
        total_days = (next_level_date - level_start_date).days
        elapsed_days = (current_date - level_start_date).days
        
        if total_days > 0:
            level_progress = min(100, round((elapsed_days / total_days) * 100))
    
    # Build response data with more efficient structure
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
            # Process sessions directly here instead of looping later
            'upcoming': [
                {
                    'id': counseling.id,
                    'title': counseling.title,
                    'scheduled_date': counseling.scheduled_date,
                    'type': counseling.counseling_type.name if counseling.counseling_type else "General"
                } for counseling in upcoming_counseling
            ],
            'completed': recent_completed_with_notes,
            'needNotes': [
                {
                    'id': counseling.id,
                    'title': counseling.title,
                    'scheduled_date': counseling.scheduled_date,
                    'type': counseling.counseling_type.name if counseling.counseling_type else "General"
                } for counseling in sessions_needing_notes
            ]
        },
        'stats': {
            'totalSessions': nurse_counseling.count(),
            'completedSessions': completed_counseling.count(),
            'pendingNotes': sessions_needing_notes.count()
        }
    }
    
    # Cache the response data
    cache.set(cache_key, response_data, 60 * 2)  # 2 minutes
    
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
        # Use select_related to get status in one query
        counseling = Counseling.objects.select_related('status').get(pk=counseling_id)
        
        # Check if scheduled time has passed
        if counseling.scheduled_date and counseling.scheduled_date > timezone.now():
            return Response(
                {"error": "Cannot mark as completed before the scheduled time"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update status to completed (assuming 3 is the "completed" status code)
        COMPLETED_STATUS_ID = 3
        counseling.status_id = COMPLETED_STATUS_ID
        counseling.save(update_fields=['status_id'])  # Update only the changed field
        
        # Clear cache for dashboards since this affects metrics
        invalidate_dashboard_caches()        
        # # Create audit log for this action
        # try:
        #     AuditLog.objects.create(
        #         user=request.user,
        #         action=f"Marked counseling session #{counseling_id} as completed",
        #         action_time=timezone.now(),
        #         ip_address=request.META.get('REMOTE_ADDR', '')
        #     )
        # except Exception as audit_error:
        #     # Log the error but don't fail the request
        #     print(f"Failed to create audit log: {str(audit_error)}")
        
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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_dashboard(request):
    """Dashboard data for admin users with improved performance"""
    # Check if user is admin
    if not hasattr(request.user, 'role') or request.user.role.name.lower() != 'admin':
        return Response(
            {"error": "Only admin users can access this endpoint"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Use cache for repeated access
    cache_key = f"admin_dashboard_{request.user.id}"
    cached_data = cache.get(cache_key)
    if cached_data:
        return Response(cached_data)
    
    # Get counts more efficiently with a single query using aggregation
    user_stats = User.objects.aggregate(
        user_count=Count('id'),
        nurse_count=Count('nurse', distinct=True),
        management_count=Count('management', distinct=True)
    )
    
    department_count = Department.objects.count()
    
    # Get recent login activity with related user data
    recent_logins = LoginHistory.objects.select_related('user').order_by('-login_time')[:5]
    
    # Get active sessions (no logout time)
    active_sessions = LoginHistory.objects.filter(logout_time__isnull=True).count()
    
    # Get users by role in a single query using aggregation
    users_by_role = User.objects.values('role__name').annotate(count=Count('id'))
    
    # Build response data
    response_data = {
        'counts': {
            'users': user_stats['user_count'],
            'nurses': user_stats['nurse_count'],
            'management': user_stats['management_count'],
            'departments': department_count,
            'active_sessions': active_sessions
        },
        'recent_logins': [],
        'users_by_role': [
            {
                'role': item['role__name'] or 'Unassigned',
                'count': item['count']
            } for item in users_by_role
        ]
    }
    
    # Process recent logins
    for login in recent_logins:
        response_data['recent_logins'].append({
            'id': login.id,
            'user': {
                'id': login.user.id,
                'username': login.user.username,
                'name': f"{login.user.first_name} {login.user.last_name}"
            },
            'login_time': login.login_time,
            'logout_time': login.logout_time,
            'ip_address': login.ip_address,
            'device_info': login.device_info,
            'status': login.status
        })
    
    # Cache the response data
    cache.set(cache_key, response_data, 60 * 5)  # 5 minutes
    
    return Response(response_data)

class AdminUserViewSet(DatabaseRetryMixin, viewsets.ModelViewSet):
    """ViewSet for admin to manage users"""
    serializer_class = AdminUserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        # Check if user has admin role
        if not hasattr(user, 'role') or user.role.name.lower() != 'admin':
            return User.objects.none()
        
        # Use select_related and annotated fields for faster queries
        queryset = User.objects.select_related('role').all()
        
        # Add full name annotation for more efficient filtering
        queryset = queryset.annotate(
            full_name=Concat('first_name', Value(' '), 'last_name', output_field=CharField())
        )
        
        # Filter by search query if provided
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(full_name__icontains=search)  # Use the annotated field
            )
        
        # Filter by role if provided
        role = self.request.query_params.get('role', None)
        if role:
            queryset = queryset.filter(role__name=role)
            
        return queryset
    
    def create(self, request, *args, **kwargs):
        # Check if user is admin
        if not hasattr(request.user, 'role') or request.user.role.name.lower() != 'admin':
            return Response(
                {"error": "Only admin users can create users"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        data = request.data.copy()
        
        # Hash password if provided
        if 'password' in data and data['password']:
            data['password'] = make_password(data['password'])
        else:
            data.pop('password', None)
        
        # Set role
        if 'role' in data:
            try:
                role = Roles.objects.get(id=data['role'])
            except Roles.DoesNotExist:
                return Response(
                    {"error": "Invalid role provided"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Use database transaction to ensure atomic operation
        from django.db import transaction
        
        try:
            with transaction.atomic():
                # Create basic user first
                serializer = self.get_serializer(data=data)
                serializer.is_valid(raise_exception=True)
                user = serializer.save()
                
                # Create nurse or management profile based on user type
                if data.get('userType') == 'nurse':
                    nurse_data = {
                        'user': user.id,
                        'nurse_account_id': data.get('nurse_account_id'),
                        'current_level': data.get('level', None),
                        'hire_date': data.get('hire_date'),
                        'years_of_service': 0,  # Will be calculated on save
                        'department': data.get('department'),
                        'specialization': data.get('specialization', ''),
                        'is_active': True
                    }
                    nurse_serializer = NurseSimpleSerializer(data=nurse_data)
                    if nurse_serializer.is_valid():
                        nurse_serializer.save()
                    else:
                        # Exception in transaction will cause rollback
                        raise ValueError(nurse_serializer.errors)
                
                elif data.get('userType') == 'management':
                    management_data = {
                        'user': user.id,
                        'management_account_id': data.get('management_account_id'),
                        'department': data.get('department'),
                        'position': data.get('position', ''),
                        'is_active': True
                    }
                    management_serializer = ManagementSerializers(data=management_data)
                    if management_serializer.is_valid():
                        management_serializer.save()
                    else:
                        # Exception in transaction will cause rollback
                        raise ValueError(management_serializer.errors)
                
                # Clear admin dashboard cache
                invalidate_dashboard_caches()                
                # Return created user
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, *args, **kwargs):
        # Check if user is admin
        if not hasattr(request.user, 'role') or request.user.role.name.lower() != 'admin':
            return Response(
                {"error": "Only admin users can update users"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = self.get_object()
        data = request.data.copy()
        
        # Hash password if provided
        if 'password' in data and data['password']:
            data['password'] = make_password(data['password'])
        else:
            data.pop('password', None)
        
        # Use database transaction for atomic updates
        from django.db import transaction
        
        try:
            with transaction.atomic():
                # Update basic user info
                serializer = self.get_serializer(user, data=data, partial=True)
                serializer.is_valid(raise_exception=True)
                updated_user = serializer.save()
                
                # Update nurse or management profile based on user type
                if data.get('userType') == 'nurse':
                    # Check if nurse profile exists
                    try:
                        nurse = Nurse.objects.get(user=user)
                        nurse_data = {
                            'nurse_account_id': data.get('nurse_account_id', nurse.nurse_account_id),
                            'current_level': data.get('level', nurse.current_level_id),
                            'hire_date': data.get('hire_date', nurse.hire_date),
                            'department': data.get('department', nurse.department_id),
                            'specialization': data.get('specialization', nurse.specialization),
                        }
                        nurse_serializer = NurseSimpleSerializer(nurse, data=nurse_data, partial=True)
                        if nurse_serializer.is_valid():
                            nurse_serializer.save()
                        else:
                            raise ValueError(nurse_serializer.errors)
                    except Nurse.DoesNotExist:
                        # Create nurse profile if it doesn't exist
                        nurse_data = {
                            'user': user.id,
                            'nurse_account_id': data.get('nurse_account_id'),
                            'current_level': data.get('level', None),
                            'hire_date': data.get('hire_date'),
                            'years_of_service': 0,  # Will be calculated on save
                            'department': data.get('department'),
                            'specialization': data.get('specialization', ''),
                            'is_active': True
                        }
                        nurse_serializer = NurseSimpleSerializer(data=nurse_data)
                        if nurse_serializer.is_valid():
                            nurse_serializer.save()
                        else:
                            raise ValueError(nurse_serializer.errors)
                        
                        # Delete management profile if it exists - more efficient
                        Management.objects.filter(user=user).delete()
                        
                elif data.get('userType') == 'management':
                    # Similar optimized handling for management profile
                    try:
                        management = Management.objects.get(user=user)
                        management_data = {
                            'management_account_id': data.get('management_account_id', management.management_account_id),
                            'department': data.get('department', management.department_id),
                            'position': data.get('position', management.position),
                        }
                        management_serializer = ManagementSerializers(management, data=management_data, partial=True)
                        if management_serializer.is_valid():
                            management_serializer.save()
                        else:
                            raise ValueError(management_serializer.errors)
                    except Management.DoesNotExist:
                        # Create management profile if it doesn't exist
                        management_data = {
                            'user': user.id,
                            'management_account_id': data.get('management_account_id'),
                            'department': data.get('department'),
                            'position': data.get('position', ''),
                            'is_active': True
                        }
                        management_serializer = ManagementSerializers(data=management_data)
                        if management_serializer.is_valid():
                            management_serializer.save()
                        else:
                            raise ValueError(management_serializer.errors)
                        
                        # Delete nurse profile if it exists - more efficient
                        Nurse.objects.filter(user=user).delete()
                
                # Clear admin dashboard cache
                invalidate_dashboard_caches()                
                # Return updated user
                return Response(serializer.data)
                
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, *args, **kwargs):
        # Check if user is admin
        if not hasattr(request.user, 'role') or request.user.role.name.lower() != 'admin':
            return Response(
                {"error": "Only admin users can delete users"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Cannot delete yourself
        if request.user.id == kwargs.get('pk'):
            return Response(
                {"error": "You cannot delete your own account"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Clear cache after deletion
        response = super().destroy(request, *args, **kwargs)
        if response.status_code == 204:  # Successfully deleted
            invalidate_dashboard_caches()        
        return response
    
class LoginHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for admin to view login history"""
    serializer_class = None  # You'll need to create a serializer for this
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        # Check if user has admin role
        if not hasattr(user, 'role') or user.role.name.lower() != 'admin':
            return LoginHistory.objects.none()
        
        # Get all login history
        queryset = LoginHistory.objects.all().select_related('user')
        
        # Filter by user if provided
        user_id = self.request.query_params.get('user_id', None)
        if user_id:
            queryset = queryset.filter(user_id=user_id)
            
        # Filter by status if provided
        status = self.request.query_params.get('status', None)
        if status:
            queryset = queryset.filter(status=status)
            
        # Filter by date range if provided
        start_date = self.request.query_params.get('start_date', None)
        if start_date:
            queryset = queryset.filter(login_time__gte=start_date)
            
        end_date = self.request.query_params.get('end_date', None)
        if end_date:
            queryset = queryset.filter(login_time__lte=end_date)
            
        return queryset.order_by('-login_time')

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
            try:
                refresh = request.data.get("refresh")
                print(e)
                print(refresh)
                
                # Check if refresh token exists
                if not refresh:
                    return Response(
                        {"error": "Refresh token not provided."},
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
                
                # Try to decode the token
                try:
                    token = RefreshToken(refresh)
                    user_id = token.payload.get('user_id')
                    
                    # Check if user exists before trying to update them
                    try:
                        user = User.objects.get(id=user_id)
                        user.is_login = False
                        user.save()
                    except User.DoesNotExist:
                        # User doesn't exist but we still want to return the same error
                        print(f"User with ID {user_id} does not exist")
                        
                except (TokenError, InvalidToken):
                    # Handle invalid token format
                    print("Invalid token format")
                    
            except Exception as inner_exception:
                # Catch any other exceptions in our exception handler
                print(f"Error in exception handler: {inner_exception}")
                
            # Always return the same error message for security reasons
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
    serializer_class = CounselingSerializer
    
    def get_queryset(self):
        """
        Return a queryset filtered by user role and optimized with select_related and prefetch_related
        """
        user = self.request.user
        user_role = user.role.name.lower() if user.role else ''
        
        # Start with a base optimized queryset
        queryset = Counseling.objects.select_related(
            'management', 'status', 'counseling_type'
        ).prefetch_related(
            Prefetch('nurses_id', queryset=Nurse.objects.select_related('user', 'department', 'current_level')),
            'material_files'
        )
        
        # Apply role-based filtering
        if user_role == 'nurse':
            try:
                nurse = Nurse.objects.get(user=user)
                queryset = queryset.filter(nurses_id=nurse)
            except Nurse.DoesNotExist:
                return Counseling.objects.none()
        elif user_role == 'management':
            try:
                management = Management.objects.get(user=user)
                queryset = queryset.filter(management=management)
            except Management.DoesNotExist:
                return Counseling.objects.none()
        elif user_role != 'admin':
            return Counseling.objects.none()
        
        # Apply any search filters from request
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(description__icontains=search) |
                Q(nurses_id__user__first_name__icontains=search) |
                Q(nurses_id__user__last_name__icontains=search)
            ).distinct()
        
        # Apply status filter if provided
        status_id = self.request.query_params.get('status')
        if status_id and status_id.isdigit():
            queryset = queryset.filter(status_id=status_id)
        
        # Apply date range filter if provided
        start_date = self.request.query_params.get('start_date')
        if start_date:
            queryset = queryset.filter(scheduled_date__gte=start_date)
            
        end_date = self.request.query_params.get('end_date')
        if end_date:
            queryset = queryset.filter(scheduled_date__lte=end_date)
        
        return queryset
    
    def perform_create(self, serializer):
        """Save the counseling with current user's management profile and clear caches"""
        try:
            # Get management profile in a try-except block to prevent errors
            management = Management.objects.get(user=self.request.user)
            counseling = serializer.save(management=management)
            
            # Clear dashboard caches since a new counseling session was created
            invalidate_dashboard_caches()            
            # Create audit log entry
            # AuditLog.objects.create(
            #     user=self.request.user,
            #     action=f"Created counseling session: {counseling.title}",
            #     action_time=timezone.now(),
            #     ip_address=self.request.META.get('REMOTE_ADDR', '')
            # )
            
        except Management.DoesNotExist:
            # Fall back to default behavior if management profile doesn't exist
            serializer.save()
    
    def perform_update(self, serializer):
        """Update the counseling instance and clear caches"""
        counseling = serializer.save()
        
        # Clear dashboard caches since a counseling session was updated
        invalidate_dashboard_caches()        
        # Create audit log entry
        # AuditLog.objects.create(
        #     user=self.request.user,
        #     action=f"Updated counseling session: {counseling.title}",
        #     action_time=timezone.now(),
        #     ip_address=self.request.META.get('REMOTE_ADDR', '')
        # )
    
    def perform_destroy(self, instance):
        """Delete the counseling instance and clear caches"""
        title = instance.title
        instance.delete()
        
        # Clear dashboard caches since a counseling session was deleted
        invalidate_dashboard_caches()        
        # Create audit log entry
        # AuditLog.objects.create(
        #     user=self.request.user,
        #     action=f"Deleted counseling session: {title}",
        #     action_time=timezone.now(),
        #     ip_address=self.request.META.get('REMOTE_ADDR', '')
        # )
    
    @action(detail=True, methods=['post'])
    def remove_file(self, request, pk=None):
        """
        Remove a material file from a counseling session
        """
        counseling = self.get_object()
        file_id = request.data.get('file_id')
        
        try:
            # Use filter().exists() first to avoid fetching the object if not needed
            if not counseling.material_files.filter(id=file_id).exists():
                return Response(
                    {"detail": "File not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Remove the file
            counseling.material_files.remove(file_id)
            
            # Create audit log entry
            # AuditLog.objects.create(
            #     user=request.user,
            #     action=f"Removed file {file_id} from counseling session: {counseling.title}",
            #     action_time=timezone.now(),
            #     ip_address=request.META.get('REMOTE_ADDR', '')
            # )
            
            return Response(status=status.HTTP_204_NO_CONTENT)
            
        except Exception as e:
            return Response(
                {"detail": f"Error removing file: {str(e)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
    @action(detail=True, methods=['get'])
    @cache_page(60 * 5)  # Cache for 5 minutes
    def get_summary(self, request, pk=None):
        """
        Get a summary of the counseling session including statistics
        """
        counseling = self.get_object()
        
        # Get the notes count with a single query
        notes_count = CounselingResult.objects.filter(counseling=counseling).count()
        
        # Get the nurses count
        nurses_count = counseling.nurses_id.count()
        
        # Check if all nurses have submitted notes
        notes_complete = notes_count >= nurses_count
        
        # Build the summary data
        summary_data = {
            'id': counseling.id,
            'title': counseling.title,
            'scheduled_date': counseling.scheduled_date,
            'status': {
                'id': counseling.status.id,
                'name': counseling.status.name
            },
            'type': {
                'id': counseling.counseling_type.id if counseling.counseling_type else None,
                'name': counseling.counseling_type.name if counseling.counseling_type else 'General'
            },
            'notes_count': notes_count,
            'nurses_count': nurses_count,
            'notes_complete': notes_complete,
            'days_since_scheduled': (timezone.now().date() - counseling.scheduled_date.date()).days if counseling.scheduled_date else None
        }
        
        return Response(summary_data)
            
class CounselingResultViewSet(viewsets.ModelViewSet):
    """
    ViewSet for CounselingResult model (Session Notes) with optimized performance
    """
    serializer_class = CounselingResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['nurse_feedback', 'counseling__title', 'nurse__user__first_name', 'nurse__user__last_name']
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
        
        # Base query with optimized joins
        queryset = CounselingResult.objects.select_related(
            'counseling', 
            'counseling__status',
            'counseling__counseling_type',
            'nurse', 
            'nurse__user',
            'nurse__department',
            'nurse__current_level'
        )
        
        if role in ['management', 'admin']:
            # Management/admin can see all notes
            pass  # No additional filtering needed
        elif role == 'nurse':
            # Nurses can only see their own notes
            try:
                nurse = Nurse.objects.get(user=user)
                queryset = queryset.filter(nurse=nurse)
            except Nurse.DoesNotExist:
                return CounselingResult.objects.none()
        else:
            return CounselingResult.objects.none()
        
        # Apply filters from query parameters
        # counseling filter
        counseling = self.request.query_params.get('counseling', None)
        if counseling:
            queryset = queryset.filter(counseling_id=counseling)
            
        # Nurse filter
        nurse = self.request.query_params.get('nurse', None)
        if nurse:
            queryset = queryset.filter(nurse_id=nurse)
        
        # Date range filters
        start_date = self.request.query_params.get('start_date', None)
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
            
        end_date = self.request.query_params.get('end_date', None)
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)
            
        # Search filtering - handled by filter_backends
        
        return queryset
    
    def perform_create(self, serializer):
        """Create a note and clear relevant caches"""
        note = serializer.save()
        
        # Clear any cached data related to counseling dashboards
        invalidate_dashboard_caches()        
        # Create audit log
        # AuditLog.objects.create(
        #     user=self.request.user,
        #     action=f"Created note for counseling session #{note.counseling_id}",
        #     action_time=timezone.now(),
        #     ip_address=self.request.META.get('REMOTE_ADDR', '')
        # )
    
    def perform_update(self, serializer):
        """Update a note and clear relevant caches"""
        note = serializer.save()
        
        # Clear any cached data related to counseling dashboards
        invalidate_dashboard_caches()        
        # Create audit log
        # AuditLog.objects.create(
        #     user=self.request.user,
        #     action=f"Updated note for counseling session #{note.counseling_id}",
        #     action_time=timezone.now(),
        #     ip_address=self.request.META.get('REMOTE_ADDR', '')
        # )
    
    def perform_destroy(self, instance):
        """Delete a note and clear relevant caches"""
        counseling_id = instance.counseling_id
        instance.delete()
        
        # Clear any cached data related to counseling dashboards
        invalidate_dashboard_caches()        
        # # Create audit log
        # AuditLog.objects.create(
        #     user=self.request.user,
        #     action=f"Deleted note for counseling session #{counseling_id}",
        #     action_time=timezone.now(),
        #     ip_address=self.request.META.get('REMOTE_ADDR', '')
        # )

    @action(detail=False, methods=['get'], url_path=r'(?P<counseling_id>\d+)/nurse/(?P<nurse_id>\d+)')
    def get_note_by_counseling_and_nurse(self, request, counseling_id=None, nurse_id=None):
        """
        Get a specific note for a counseling session from a specific nurse
        """
        try:
            # Check if counseling and nurse exist (using get_object_or_404 for cleaner code)
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
            
            # Use the optimized query with select_related
            note = get_object_or_404(
                CounselingResult.objects.select_related(
                    'counseling', 
                    'nurse', 
                    'nurse__user', 
                    'nurse__department'
                ), 
                counseling=counseling, 
                nurse=nurse
            )
            
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
        
        cache_key = f"notes_by_counseling_{request.user.id}_{request.query_params}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return Response(cached_data)
        # Get query parameters
        search = request.query_params.get('search', '')
        
        # Define an optimized base query for counseling with notes
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
        
        # Optimize with prefetch_related to avoid N+1 queries
        counseling_with_notes = counseling_with_notes.prefetch_related(
            Prefetch(
                'counselingresult_set',
                queryset=CounselingResult.objects.select_related('nurse__user', 'nurse__department', 'nurse__current_level')
            ),
            Prefetch(
                'nurses_id',
                queryset=Nurse.objects.select_related('user', 'department', 'current_level')
            ),
            'status',
            'counseling_type',
            'management__user'
        )
        
        # Pagination for large result sets
        page_size = int(request.query_params.get('page_size', 20))
        page = int(request.query_params.get('page', 1))
        
        start = (page - 1) * page_size
        end = start + page_size
        
        # Apply slice for pagination
        paginated_counseling = counseling_with_notes[start:end]
        
        # Serialize the data
        result = []
        for counseling in paginated_counseling:
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
        
        # Add pagination metadata
        total_count = counseling_with_notes.count()
        pagination = {
            'total_count': total_count,
            'total_pages': (total_count + page_size - 1) // page_size,
            'current_page': page,
            'page_size': page_size
        }
        
        response_data = {
            'pagination': pagination,
            'results': result
        }
        
        cache.set(cache_key, response_data, 60 * 5)  # 5 minutes
        return Response(response_data)
        
class RolesViewSet(viewsets.ModelViewSet):
    queryset = Roles.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]   
                  
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