from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    NurseViewSet,
    LevelReferenceViewSet,
    DepartmentViewSet,
    ConsultationTypesViewSet,
    ConsultationStatusViewSet,
    LevelUpgradeStatusViewSet,
    LevelHistoryViewSet,
    UserRegistrationView,
    LoginView,
    LogoutApiView,
    ChangePasswordView,
    RequestPasswordResetView,
    ResetPasswordConfirmView,
    TestAuthView,
    NurseLevelView,
    ConsultationsViewSet,
    ConsultationResultViewSet,
    MaterialReadStatusViewSet,
    ConsultationMaterialsViewSet,
    AuditLogViewSet,
    ManagementViewSet,
    SystemConfigurationViewSet,
    TokenIdentifyView,
    ) 


router = DefaultRouter()
router.register(r'nurses', NurseViewSet, basename='nurse')
router.register(r'levels', LevelReferenceViewSet, basename='level')
router.register(r'levelstatus', LevelUpgradeStatusViewSet, basename='level-status')
router.register(r'management', ManagementViewSet, basename='management')
router.register(r'department', DepartmentViewSet, basename='department')
router.register(r'consultationtype', ConsultationTypesViewSet, basename='consultation-type')
router.register(r'consultationstatus', ConsultationStatusViewSet, basename='consultation-status')
router.register(r'levelhistory', LevelHistoryViewSet, basename='level-history')
router.register(r'consultations', ConsultationsViewSet, basename='consultations')
router.register(r'consultationresult', ConsultationResultViewSet, basename='consultation-result')
router.register(r'consusultationreadstatus', MaterialReadStatusViewSet, basename='consultation-read-status')
router.register(r'consultationmaterial', ConsultationMaterialsViewSet, basename='consultation-material')
router.register(r'auditlog', AuditLogViewSet, basename='audit-log')
router.register(r'systemconfiguration', SystemConfigurationViewSet, basename='system-configuration')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutApiView.as_view(), name='logout'),
    path('test/', TestAuthView.as_view(), name='test'),
    path('verifytoken/', TokenIdentifyView.as_view(), name ='token-identify'),
    path('nurse-level/', NurseLevelView.as_view(), name='nurse-level'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('request-password-reset/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('reset-password-confirm/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    
       
]