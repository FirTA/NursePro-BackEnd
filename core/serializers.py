from rest_framework import serializers
from django.utils import timezone

from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import (
    Roles,
    User,
    Management,
    Nurse,
    LevelReference,
    LevelUpgradeStatus,
    LevelUpgradeRequests,
    LevelHistory,
    Nurse,
    MaterialReadStatus,
    Department,
    Consultations,
    ConsultationTypes,
    ConsultationStatus,
    CounselingMaterials,
    ConsultationResult,
    SystemConfiguration,
    AuditLog,
    Materials    
)


from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

def generate_tokens(user, username, role):
    """
    Generates access and refresh tokens with custom claims.

    Args:
        user (User): The Django user object.
        nama_user (str): The name of the user.
        role (str): The role of the user.

    Returns:
        dict: A dictionary containing the access token and refresh token.
    """
    refresh = RefreshToken.for_user(user)
    refresh['username'] = username
    refresh['role'] = role
    
    access = refresh.access_token    
    access['username'] = username
    access['role'] = role
    
    print("request validate token")

    return {
        'access': str(access),
        'refresh': str(refresh),
    }
    
class UserRegistrationSerializers(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=155, min_length=5)
    password=serializers.CharField(max_length=1000, write_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)
    class Meta:
        model = User
        fields = [ 'username', 'password', 'access_token', 'refresh_token']
        
    default_error_messages = {
        'invalid_account' : ('invalid credential try again'),
        'is_login' : 'User already log in'
    }

    

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        request=self.context.get('request')
        
        user = authenticate(request, username=username, password=password)        

        if not user:
            raise AuthenticationFailed('invalid credential try again')
        
        if user.is_login:
            print("User already log in")
            raise AuthenticationFailed('User already log in')

        # if not user.is_verified:
        #     raise AuthenticationFailed("Email is not verified")
        # print(user.role.role_name)
        tokens=generate_tokens(user, username, user.role.role_name)
        user.is_login = True
        user.save()
        
        return {
            'user_id'       : user.pk,
            'username'      : user.username,
            'role'          : user.role.role_name,
            "access_token"  : str(tokens['access']),
            "refresh_token" : str(tokens['refresh']),
        }

class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    
    default_error_messages = {
        'bad_token' : ('Token is expired or invalid')
    }
    
    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        
        return attrs
    
    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
            return {
                "massage" : "log out successfully"
            }
        except TokenError as e:
            print(f"token error : {e}") 
            return self.fail('bad_token')            

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        return attrs

class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        return attrs

class UserSerializer(serializers.ModelSerializer):
    class Meta :
        model = User
        fields = ['id', 'username', 'email', 'role', 'phone']
        read_only_fields = ['role']
        
class NurseSerializer(serializers.ModelSerializer):
    user = UserSerializer().data.get('username')
    current_level_name = serializers.CharField(source='current_level.name', read_only=True)
    
    
    class Meta:
        model = Nurse
        fields = ['id', 'user', 'current_level', 'current_level_name', 'specialization', 'is_active']
             
class UserCreateSerializer(serializers.ModelSerializer):
    nurse_id = serializers.CharField(required=True)
    
    class Meta:
        model = User
        fields = ['nurse_id', 'username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_nurse_id(self, value):
        # Check if nurse ID exists in the management system
        if not self.validate_nurse_id_in_management_system(value):
            raise serializers.ValidationError("Invalid Nurse ID")
        return value

    def validate_nurse_id_in_management_system(self, nurse_id):
        # Add your logic to validate nurse ID against management system
        # This could be an API call or database check
        return True  # Placeholder return

    def create(self, validated_data):
        nurse_id = validated_data.pop('nurse_id')
        # Fetch nurse details from management system
        nurse_details = self.get_nurse_details_from_management(nurse_id)
        
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            nurse_id=nurse_id,
            role='nurse',
            department=nurse_details.get('department', '')
        )
        
        # Create associated nurse profile
        Nurse.objects.create(
            user=user,
            current_level=LevelReference.objects.get(code=nurse_details.get('initial_level', '1-A')),
            years_of_service=nurse_details.get('years_of_service', 0)
        )
        
        return user

    def get_nurse_details_from_management(self, nurse_id):
        # Add your logic to fetch nurse details from management system
        # This could be an API call or database check
        return {
            'department': 'General',
            'initial_level': '1-A',
            'years_of_service': 0
        }
        
""""
list parameter :
- Level
- Level Upgrade Status
- Department
- Consultation Type
- Consultation Status
"""        
class LevelReferenceSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)
    next_level = serializers.CharField(allow_blank=True, required=False)  # Add this line
        
    class Meta:
        model = LevelReference
        fields = ['id','level','next_level','required_time_in_month', 'created_at', 'update_at']
        read_only_fields = ['created_at','updated_at']
    
class LevelHistorySerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = LevelHistory
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
class LevelUpgradeStatusSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = LevelUpgradeStatus
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
class DepartmentSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = Department
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']

class ConsultationTypesSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = ConsultationTypes
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
class ConsultationStatusSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = ConsultationStatus
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
                       

"""
Level Upgrade
"""          
class LevelRequestUpdateSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = LevelUpgradeRequests
        fields = 'nurse'
        read_only_fields = ['created_at','updated_at']
                       
class ConsultationSerializer(serializers.ModelSerializer):
    nurses = NurseSerializer(many=True, source = 'nurses_id')  # Karena ManyToManyField
    created_at = serializers.DateTimeField(default=timezone.now)
    updated_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = Consultations
        fields = ['title', 'nurses','created_at','updated_at']
        read_only_fields = ['created_at','updated_at']
        
class CounselingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Consultations
        fields = ["title"]

class MaterialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Materials
        fields = ["title","file_path","size_readable","created_at"]

class CounselingMaterialSerializer(serializers.ModelSerializer):
    counseling_title = serializers.CharField( source = 'counseling.title',read_only = True)
    file = MaterialSerializer(many = True)
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = CounselingMaterials
        fields = ['id','counseling_title', 'description', 'file','created_at','update_at']
        read_only_fields = ['created_at','updated_at']
        
class CounselingMaterialCreateSerializer(serializers.ModelSerializer):
    class MaterialCreateSerializer(serializers.ModelSerializer):
        file_path = serializers.FileField(required = False)
        class Meta:
            model = Materials
            fields = ('file_path',)
        
    file = MaterialCreateSerializer(many = True, required = False)
    
    def update(self, instance, validated_data):
        
        print(validated_data, self)
        material_data = self.context['request'].FILES.getlist('file')
        
        instance.description = validated_data.get('description', instance.description)  
        instance.save()      
        # instance = super().update(instance, validated_data)
                
        if material_data: 
            # clear existing item
            instance.file.clear()
            
            print(instance)
            
            # Recreate items with updated data
            for data in material_data:
                material_instance = Materials.objects.create(file_path=data)
                instance.file.add(material_instance)
        return instance
    
    class Meta:
        model = CounselingMaterials
        fields = (
            'description',
            'file'
        )
        

class ConsultationResultSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = ConsultationResult
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
class MaterialReadStatusSerializers(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = MaterialReadStatus
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
class SystemConfigurationSerializers(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = SystemConfiguration
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
class AuditLogSerializers(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = AuditLog
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']

class ManagementSerializers(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = Management
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']