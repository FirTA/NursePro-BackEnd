from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
import random
import faker

from core.models import (
    Roles, User, Department, LevelReferences, 
    Nurse, Management, ConsultationTypes, 
    ConsultationStatus, Consultations, 
    ConsultationMaterials, LevelUpgradeStatus, 
    LevelUpgradeRequests, SystemConfiguration
)

class Command(BaseCommand):
    help = 'Seeds the database with comprehensive data for Nurse Management System'

    def handle(self, *args, **kwargs):
        # Clear existing data
        models_to_clear = [
            Roles, User, Department, LevelReferences, 
            Nurse, Management, ConsultationTypes, 
            ConsultationStatus, Consultations, 
            ConsultationMaterials, LevelUpgradeStatus, 
            LevelUpgradeRequests, SystemConfiguration
        ]
        for model in models_to_clear:
            model.objects.all().delete()

        # Create Faker instance
        fake = faker.Faker()

        # Seed Roles (Updated)
        roles_data = ['Admin', 'Management', 'Nurse']
        roles = {role: Roles.objects.create(role_name=role) for role in roles_data}

        # Seed Departments
        departments = [
            Department.objects.create(department=dept) 
            for dept in ['Cardiology', 'Pediatrics', 'Emergency', 'Oncology', 'Neurology']
        ]

        # Seed Level References
        level_refs = [
            LevelReferences.objects.create(
                level=level, 
                required_time=timezone.now()
            ) for level in ['1-A', '1-B', '2-A', '2-B', '3-A', '3-B']
        ]

        # Seed Consultation Types
        consultation_types = [
            ConsultationTypes.objects.create(
                name='Regular Consultation', 
                description='Routine professional development consultation'
            ),
            ConsultationTypes.objects.create(
                name='Violation Follow-up', 
                description='Consultation to address professional conduct issues'
            )
        ]

        # Seed Consultation Status
        consultation_statuses = [
            ConsultationStatus.objects.create(
                name='Scheduled', 
                description='Consultation is planned and upcoming'
            ),
            ConsultationStatus.objects.create(
                name='In Progress', 
                description='Consultation is currently happening'
            ),
            ConsultationStatus.objects.create(
                name='Completed', 
                description='Consultation has been finished'
            )
        ]

        # Seed Level Upgrade Status
        level_upgrade_statuses = [
            LevelUpgradeStatus.objects.create(status_name='Pending'),
            LevelUpgradeStatus.objects.create(status_name='Approved'),
            LevelUpgradeStatus.objects.create(status_name='Rejected')
        ]

        # System Configuration
        SystemConfiguration.objects.bulk_create([
            SystemConfiguration(config_key='CONSULTATION_FREQUENCY', config_value='3 times every 2 months'),
            SystemConfiguration(config_key='AUTO_LEVEL_UPGRADE', config_value='yearly'),
            SystemConfiguration(config_key='MAX_LOGIN_ATTEMPTS', config_value='5'),
            SystemConfiguration(config_key='PASSWORD_RESET_TIMEOUT', config_value='30')
        ])

        # Create Admin User
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@hospital.com',
            password='AdminPass123!',
            first_name='System',
            last_name='Administrator',
            role=roles['Admin'],
            email_verified=True
        )

        # Generate Management and Nurse Users
        management_users = []
        nurse_users = []

        # 10 Management Users
        for i in range(10):
            management_user = User.objects.create_user(
                username=f'management{i+1}',
                email=f'management{i+1}@hospital.com',
                password=f'ManagementPass{i+1}!',
                first_name=fake.first_name(),
                last_name=fake.last_name(),
                role=roles['Management'],
                email_verified=True
            )
            management_instance = Management.objects.create(
                management_account_id=f'MGT{i+1:03d}',
                user_id=management_user,
                department=random.choice(departments),
                position=random.choice(['Department Head', 'Nurse Manager', 'Senior Coordinator'])
            )
            management_users.append(management_instance)

        # 15 Nurse Users
        for i in range(15):
            nurse_user = User.objects.create_user(
                username=f'nurse{i+1}',
                email=f'nurse{i+1}@hospital.com',
                password=f'NursePass{i+1}!',
                first_name=fake.first_name(),
                last_name=fake.last_name(),
                role=roles['Nurse'],
                email_verified=True
            )
            nurse_instance = Nurse.objects.create(
                nurse_account_id=f'NURSE{i+1:03d}',
                user=nurse_user,
                current_level=random.choice(level_refs[:3]),
                hire_date=timezone.now().date() - timedelta(days=random.randint(100, 1500)),
                years_of_service=timezone.now().date(),
                department=random.choice(departments),
                specialization=random.choice(['Cardiac Care', 'Pediatric Care', 'Emergency Response', 'Oncology Support'])
            )
            nurse_users.append(nurse_instance)

        # Generate Consultations
        consultations = []
        for i in range(20):
            consultation = Consultations.objects.create(
                title=f'Consultation {i+1}',
                management=random.choice(management_users),
                consultation_type=random.choice(consultation_types),
                description=fake.text(max_nb_chars=200),
                scheduled_date=timezone.now() + timedelta(days=random.randint(1, 90)),
                status=random.choice(consultation_statuses)
            )
            # Randomly assign nurses to consultations
            consultation.nurses_id.add(*random.sample(nurse_users, random.randint(1, 3)))
            consultations.append(consultation)

        # Generate Consultation Materials
        for consultation in consultations:
            ConsultationMaterials.objects.create(
                consultation=consultation,
                title=f'Material for {consultation.title}',
                description=fake.text(max_nb_chars=100),
                file_path=f'documents/consultation_material_{consultation.id}.pdf'
            )

        # Generate Level Upgrade Requests
        for nurse in nurse_users:
            LevelUpgradeRequests.objects.create(
                nurse=nurse,
                management=random.choice(management_users),
                requested_level=random.choice(level_refs[1:]),
                current_level=nurse.current_level,
                request_date=timezone.now().date(),
                status=random.choice(level_upgrade_statuses),
                approval_date=timezone.now().date()
            )

        self.stdout.write(self.style.SUCCESS('Comprehensive database seeding completed successfully!'))