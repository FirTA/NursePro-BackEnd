# from rest_framework import serializers
# from .models import User,Nurse
# from Apps.levels.models import LevelCategory

# class UserSerializer(serializers.ModelSerializer):
#     class Meta :
#         model = User
#         fields = ['id', 'username', 'email', 'role', 'department', 'account_id', 'phone']
#         read_only_fields = ['role']
        
# class NurseSerializer(serializers.ModelSerializer):
#     user = UserSerializer()
#     current_level_name = serializers.CharField(source='current_level.name', read_only=True)

#     class Meta:
#         model = Nurse
#         fields = ['id', 'user', 'current_level', 'current_level_name', 
#                  'years_of_service', 'specialization', 'is_active']
        
        

# class UserCreateSerializer(serializers.ModelSerializer):
#     nurse_id = serializers.CharField(required=True)
    
#     class Meta:
#         model = User
#         fields = ['nurse_id', 'username', 'password']
#         extra_kwargs = {'password': {'write_only': True}}

#     def validate_nurse_id(self, value):
#         # Check if nurse ID exists in the management system
#         if not self.validate_nurse_id_in_management_system(value):
#             raise serializers.ValidationError("Invalid Nurse ID")
#         return value

#     def validate_nurse_id_in_management_system(self, nurse_id):
#         # Add your logic to validate nurse ID against management system
#         # This could be an API call or database check
#         return True  # Placeholder return

#     def create(self, validated_data):
#         nurse_id = validated_data.pop('nurse_id')
#         # Fetch nurse details from management system
#         nurse_details = self.get_nurse_details_from_management(nurse_id)
        
#         user = User.objects.create_user(
#             username=validated_data['username'],
#             password=validated_data['password'],
#             nurse_id=nurse_id,
#             role='nurse',
#             department=nurse_details.get('department', '')
#         )
        
#         # Create associated nurse profile
#         Nurse.objects.create(
#             user=user,
#             current_level=LevelCategory.objects.get(code=nurse_details.get('initial_level', '1-A')),
#             years_of_service=nurse_details.get('years_of_service', 0)
#         )
        
#         return user

#     def get_nurse_details_from_management(self, nurse_id):
#         # Add your logic to fetch nurse details from management system
#         # This could be an API call or database check
#         return {
#             'department': 'General',
#             'initial_level': '1-A',
#             'years_of_service': 0
#         }