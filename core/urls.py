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
    ConsultationResultViewSet,
    MaterialReadStatusViewSet,
    CounselingMaterialsViewSet,
    AuditLogViewSet,
    ManagementViewSet,
    SystemConfigurationViewSet,
    TokenIdentifyView,
    CustomTokenRefresh,
    get_user_profile,
    get_user_profile_page,
    update_profile_picture,
    update_user_profile
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
router.register(r'consultationresult', ConsultationResultViewSet, basename='consultation-result')
router.register(r'consusultationreadstatus', MaterialReadStatusViewSet, basename='consultation-read-status')
router.register(r'counselingmaterial', CounselingMaterialsViewSet, basename='counseling-material')
router.register(r'auditlog', AuditLogViewSet, basename='audit-log')
router.register(r'systemconfiguration', SystemConfigurationViewSet, basename='system-configuration')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutApiView.as_view(), name='logout'),
    path('test/', TestAuthView.as_view(), name='test'),
    path('api/user/profile', get_user_profile, name='user-profile'),
    path('refresh-token/', CustomTokenRefresh.as_view(), name ='refresh-token'),
    path('verifytoken/', TokenObtainPairView.as_view(), name ='token-identify'),
    path('nurse-level/', NurseLevelView.as_view(), name='nurse-level'),
    path('user/profile/', get_user_profile_page, name='user-profile'),
    path('user/profile/update/', update_user_profile, name='update-profile'),
    path('user/profile/photo/', update_profile_picture, name='update-photo'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('request-password-reset/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('reset-password-confirm/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    
       
]