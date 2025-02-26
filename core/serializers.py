from rest_framework import serializers
from django.utils import timezone
import base64
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
    Nurse,
    Department,
    Counseling,
    CounselingTypes,
    CounselingStatus,
    CounselingResult,
    SystemConfiguration,
    AuditLog,
    Materials,LoginHistory    
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
        tokens=generate_tokens(user, username, user.role.name)
        user.is_login = True
        user.save()
        
        return {
            'user_id'       : user.pk,
            'username'      : user.username,
            'role'          : user.role.name,
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
class LoginHistoryUserSerializer(serializers.ModelSerializer):
    """Serializer for simplified User data in LoginHistory"""
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'full_name', 'role']
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

class LoginHistorySerializer(serializers.ModelSerializer):
    """Serializer for LoginHistory model"""
    user = LoginHistoryUserSerializer(read_only=True)
    session_duration = serializers.SerializerMethodField()
    
    class Meta:
        model = LoginHistory
        fields = [
            'id', 'user', 'login_time', 'logout_time', 
            'ip_address', 'device_info', 'status',
            'session_duration'
        ]
    
    def get_session_duration(self, obj):
        """Calculate session duration in seconds"""
        if obj.login_time and obj.logout_time:
            duration = (obj.logout_time - obj.login_time).total_seconds()
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            seconds = int(duration % 60)
            return f"{hours}h {minutes}m {seconds}s"
        return None
    
class AdminUserSerializer(serializers.ModelSerializer):
    """Serializer for admin to manage users"""
    role_name = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()
    user_type = serializers.SerializerMethodField()
    nurse_details = serializers.SerializerMethodField()
    management_details = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 
            'role', 'role_name', 'is_active', 'phone', 'user_type', 
            'department', 'nurse_details', 'management_details','password','is_login' 
        ]
        read_only_fields = ['role_name', 'user_type', 'department', 'nurse_details', 'management_details']
    
    def get_role_name(self, obj):
        return obj.role.name if obj.role else None
    
    def get_user_type(self, obj):
        if hasattr(obj, 'nurse') and obj.nurse:
            return 'nurse'
        elif hasattr(obj, 'management') and obj.management:
            return 'management'
        return None
    
    def get_department(self, obj):
        department = None
        if hasattr(obj, 'nurse') and obj.nurse and obj.nurse.department:
            department = obj.nurse.department
        elif hasattr(obj, 'management') and obj.management and obj.management.department:
            department = obj.management.department
        
        if department:
            return {
                'id': department.id,
                'name': department.name
            }
        return None
    
    def get_nurse_details(self, obj):
        if hasattr(obj, 'nurse') and obj.nurse:
            return {
                'id': obj.nurse.id,
                'nurse_account_id': obj.nurse.nurse_account_id,
                'current_level': obj.nurse.current_level.level if obj.nurse.current_level else None,
                'hire_date': obj.nurse.hire_date,
                'years_of_service': obj.nurse.years_of_service,
                'specialization': obj.nurse.specialization,
                'is_active': obj.nurse.is_active
            }
        return None
    
    def get_management_details(self, obj):
        if hasattr(obj, 'management') and obj.management:
            return {
                'id': obj.management.id,
                'management_account_id': obj.management.management_account_id,
                'position': obj.management.position,
                'is_active': obj.management.is_active
            }
        return None

        
class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ['id', 'name']
        
class UserSerializer(serializers.ModelSerializer):
    class Meta :
        model = User
        fields = ['id', 'username', 'email', 'role', 'phone']
        read_only_fields = ['role']
        
class NurseSerializer(serializers.ModelSerializer):
    department = DepartmentSerializer()
    name = serializers.SerializerMethodField()
    level = serializers.CharField(source='current_level.level', read_only=True)

    class Meta:
        model = Nurse
        fields = ['id','nurse_account_id', 'name', 'level','department', 'level_upgrade_date', 'years_of_service','specialization','is_active']

    def get_name(self, obj):
        return f"Ns. {obj.user.first_name} {obj.user.last_name}"

    def update(self, instance, validated_data):
        # Handle the nested department data if it exists
        department_data = validated_data.pop('department', None)
        
        # Update the nurse instance with the remaining validated data
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        # If department data was provided, update the department
        if department_data and 'id' in department_data:
            # Just associate with an existing department by ID
            try:
                department = Department.objects.get(id=department_data['id'])
                instance.department = department
            except Department.DoesNotExist:
                pass
        
        instance.save()
        return instance

class ManagementSerializer(serializers.ModelSerializer):
    department = DepartmentSerializer()

    class Meta:
        model = Management
        fields = ['management_account_id', 'position', 'department']

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Roles
        fields = ['id', 'name']

class UserProfileSerializer(serializers.ModelSerializer):
    role = RoleSerializer()
    nurse = NurseSerializer()
    management = ManagementSerializer()
    class Meta:
        model = User
        fields = [
            'id', 
            'first_name', 
            'last_name',
            'phone', 
            'email', 
            'role', 
            'nurse', 
            'management',
            'profile_picture',
        ]

    def get_profile_picture(self, obj):
        if obj.profile_picture:
            return base64.b64encode(obj.profile_picture).decode()
        return None

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



class LevelUpgradeStatusSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    update_at = serializers.DateTimeField(default=timezone.now)    
    
    class Meta:
        model = LevelUpgradeStatus
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']


class CounselingTypesSerializer(serializers.ModelSerializer): 
    
    class Meta:
        model = CounselingTypes
        fields = ['id','name']
        
class CounselingStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = CounselingStatus
        fields = ['id','name']
     

class MaterialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Materials
        fields = ["id","title","file_path","size_readable","created_at"]
        read_only_fields = ['size_readable','created_at']
    def validate_file_path(self, value):
        if value.content_type != 'application/pdf':
            raise serializers.ValidationError("Only PDF files are allowed")
        return value

class ManagementSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = Management
        fields = ['management_account_id', 'position', 'name']

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"

class NurseDetailSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    level = serializers.CharField(source='current_level.name', read_only=True)

    class Meta:
        model = Nurse
        fields = ['id','nurse_account_id', 'name', 'level']

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"
                       
class CounselingSerializer(serializers.ModelSerializer):
    nurses = NurseDetailSerializer(source='nurses_id', many=True, read_only=True)
    nurse_ids = serializers.PrimaryKeyRelatedField(
        source='nurses_id',
        queryset=Nurse.objects.all(),
        many=True,
        required=False  # Made optional to fix the empty nurses issue
    )
    management = ManagementSerializer(read_only=True)
    materials_files = MaterialSerializer(source='material_files', many=True, read_only=True)
    uploaded_files = serializers.ListField(
        child=serializers.FileField(max_length=100000),
        write_only=True,
        required=False
    )
    status_display = serializers.CharField(source='status.name', read_only=True)
    counseling_type_display = serializers.CharField(source='counseling_type.name', read_only=True)

    class Meta:
        model = Counseling
        fields = [
            'id', 'title', 'description', 'nurses', 'nurse_ids',
            'management', 'counseling_type', 'counseling_type_display',
            'status', 'status_display', 'scheduled_date',
            'material_description', 'materials_files', 'uploaded_files',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def create(self, validated_data):
        nurses = validated_data.pop('nurses_id', [])
        uploaded_files = validated_data.pop('uploaded_files', [])
        
        counseling = Counseling.objects.create(**validated_data)
        if nurses:  # Add check for nurses
            counseling.nurses_id.set(nurses)
            
        for file in uploaded_files:
            material = Materials.objects.create(file_path=file)
            counseling.material_files.add(material)
        return counseling

    def update(self, instance, validated_data):
        nurses = validated_data.pop('nurses_id', None)  # Changed from [] to None
        uploaded_files = validated_data.pop('uploaded_files', [])
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if nurses is not None:  # Only update nurses if provided
            instance.nurses_id.set(nurses)
        
        # Handle files
        if uploaded_files:  # Only handle files if new ones are uploaded
            for file in uploaded_files:
                material = Materials.objects.create(file_path=file)
                instance.material_files.add(material)
        
        instance.save()
        return instance



class CounselingSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Counseling
        fields = ['id', 'title', 'scheduled_date', 'status']

class CounselingResultSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(default=timezone.now)
    updated_at = serializers.DateTimeField(default=timezone.now)
    
    # Add nested serializers
    consultation = CounselingSimpleSerializer(read_only=True)
    nurse = NurseSerializer(read_only=True)
    
    # Add write fields for IDs (used when creating/updating)
    consultation_id = serializers.PrimaryKeyRelatedField(
        queryset=Counseling.objects.all(), 
        source='consultation',
        write_only=True
    )
    nurse_id = serializers.PrimaryKeyRelatedField(
        queryset=Nurse.objects.all(),
        source='nurse',
        write_only=True
    )
   
    class Meta:
        model = CounselingResult
        fields = [
            'id', 'consultation', 'nurse', 'nurse_feedback', 
            'created_at', 'updated_at', 'consultation_id', 'nurse_id'
        ]
        read_only_fields = ['created_at', 'updated_at']
        
        
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
        
class NurseSimpleSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    level = serializers.CharField(source='current_level.level', read_only=True)

    class Meta:
        model = Nurse
        fields = '__all__'
        read_only_fields = ['created_at','updated_at']
        
    def get_name(self, obj):
        return f"Ns. {obj.user.first_name} {obj.user.last_name}"
