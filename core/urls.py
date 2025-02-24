from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    NurseViewSet,
    LevelReferenceViewSet,
    DepartmentViewSet,
    ConsultationTypesViewSet,
    ConsultationStatusViewSet,
    LevelUpgradeStatusViewSet,
    UserRegistrationView,
    LoginView,
    LogoutApiView,
    ChangePasswordView,
    RequestPasswordResetView,
    ResetPasswordConfirmView,
    TestAuthView,
    NurseLevelView,
    CounselingViewSet,
    CounselingResultViewSet,
    AuditLogViewSet,
    ManagementViewSet,
    SystemConfigurationViewSet,
    TokenIdentifyView,
    CustomTokenRefresh,
    get_user_profile,
    get_user_profile_page,
    update_profile_picture,
    update_user_profile,
    mark_counseling_completed,
    management_dashboard,
    nurse_dashboard,
    ) 
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

router = DefaultRouter()
router.register(r'nurses', NurseViewSet, basename='nurse')
router.register(r'levels', LevelReferenceViewSet, basename='level')
router.register(r'levelstatus', LevelUpgradeStatusViewSet, basename='level-status')
router.register(r'managements', ManagementViewSet, basename='management')
router.register(r'departments', DepartmentViewSet, basename='departments')
router.register(r'counseling-types', ConsultationTypesViewSet, basename='counseling-type')
router.register(r'counseling-status', ConsultationStatusViewSet, basename='counseling-status')
router.register(r'counseling', CounselingViewSet, basename='counseling')
router.register(r'counseling-results', CounselingResultViewSet, basename='counseling-results')
router.register(r'auditlog', AuditLogViewSet, basename='audit-log')
router.register(r'systemconfiguration', SystemConfigurationViewSet, basename='system-configuration')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutApiView.as_view(), name='logout'),
    path('api/user/profile', get_user_profile, name='user-profile'),
    path('refresh-token/', CustomTokenRefresh.as_view(), name ='refresh-token'),
    path('verifytoken/', TokenObtainPairView.as_view(), name ='token-identify'),
    path('nurse-level/', NurseLevelView.as_view(), name='nurse-level'),
    path('user/profile/', get_user_profile_page, name='user-profile'),
    path('counseling/<int:counseling_id>/mark-completed/', mark_counseling_completed, name='mark-counseling-completed'),
    path('user/profile/update/', update_user_profile, name='update-profile'),
    path('user/profile/photo/', update_profile_picture, name='update-photo'),
    path('dashboard/management/', management_dashboard, name='management-dashboard'),
    path('dashboard/nurse/', nurse_dashboard, name='nurse-dashboard'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('request-password-reset/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('reset-password-confirm/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    
       
]