# Save this file as core/management/commands/test_supabase_storage.py

import os
from django.core.management.base import BaseCommand
from django.core.files.base import ContentFile
from django.utils import timezone
from django.conf import settings
from django.core.files.storage import default_storage
from core.models import Materials

class Command(BaseCommand):
    help = 'Test Supabase storage integration'

    def add_arguments(self, parser):
        parser.add_argument(
            '--local-file',
            dest='local_file',
            help='Path to a local file to upload (optional)',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting Supabase storage test'))
        
        # Test configuration
        self.stdout.write("Testing configuration...")
        self.stdout.write(f"SUPABASE_URL: {settings.SUPABASE_URL}")
        self.stdout.write(f"SUPABASE_BUCKET_NAME: {settings.SUPABASE_BUCKET_NAME}")
        self.stdout.write(f"DEFAULT_FILE_STORAGE: {settings.DEFAULT_FILE_STORAGE}")
        
        # Create test content
        test_filename = f"test-file-{timezone.now().strftime('%Y%m%d%H%M%S')}.txt"
        test_content = f"This is a test file created at {timezone.now().isoformat()}"
        
        # Test 1: Direct storage operations
        self.stdout.write("\nTest 1: Testing direct storage operations...")
        try:
            # Upload test content
            self.stdout.write("Uploading test file...")
            
            if options['local_file']:
                # Use provided local file
                local_path = options['local_file']
                self.stdout.write(f"Using local file: {local_path}")
                with open(local_path, 'rb') as f:
                    test_content = f.read()
                    test_filename = os.path.basename(local_path)
            
            # Save the file
            file_path = os.path.join('test', test_filename)
            default_storage.save(file_path, ContentFile(test_content if isinstance(test_content, bytes) else test_content.encode('utf-8')))
            
            # Check if file exists
            self.stdout.write("Checking if file exists...")
            exists = default_storage.exists(file_path)
            self.stdout.write(f"File exists: {exists}")
            
            # Get URL
            self.stdout.write("Getting URL...")
            url = default_storage.url(file_path)
            self.stdout.write(f"File URL: {url}")
            
            # Get size if available
            try:
                size = default_storage.size(file_path)
                self.stdout.write(f"File size: {size} bytes")
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"Could not get file size: {e}"))
            
            # Delete the file
            # self.stdout.write("Deleting file...")
            # default_storage.delete(file_path)
            # self.stdout.write("File deleted")
            
            # Verify deletion
            exists_after_delete = default_storage.exists(file_path)
            self.stdout.write(f"File exists after deletion: {exists_after_delete}")
            
            test1_result = "PASSED" if exists and not exists_after_delete else "FAILED"
            self.stdout.write(self.style.SUCCESS(f"Test 1 result: {test1_result}"))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Test 1 ERROR: {str(e)}"))
        
        # Test 2: Using the Materials model
        self.stdout.write("\nTest 2: Testing with Materials model...")
        try:
            # Create a new Materials instance
            self.stdout.write("Creating Materials instance...")
            
            if options['local_file']:
                # Use provided local file
                local_path = options['local_file']
                with open(local_path, 'rb') as f:
                    test_content = f.read()
                    test_filename = os.path.basename(local_path)
            
            # Create a test file
            test_file = ContentFile(
                test_content if isinstance(test_content, bytes) else test_content.encode('utf-8'), 
                name=test_filename
            )
            
            # Create and save the Materials object
            material = Materials(title=f"Test Material {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")
            material.file_path.save(test_filename, test_file)
            material.save()
            
            self.stdout.write(f"Material created with ID: {material.id}")
            self.stdout.write(f"Title: {material.title}")
            self.stdout.write(f"File path: {material.file_path.name}")
            self.stdout.write(f"File URL: {material.file_path.url}")
            self.stdout.write(f"Size: {material.size} bytes")
            self.stdout.write(f"Human-readable size: {material.size_readable}")
            self.stdout.write(f"Created at: {material.formatted_created_at}")
            
            # Test retrieving
            retrieved_material = Materials.objects.get(id=material.id)
            self.stdout.write(f"Retrieved material with title: {retrieved_material.title}")
            
            # Cleanup - delete the material
            # self.stdout.write("Deleting material...")
            # material_id = material.id
            # material.delete()
            
            # Verify deletion
            material_exists = Materials.objects.filter(id=material_id).exists()
            self.stdout.write(f"Material exists after deletion: {material_exists}")
            
            test2_result = "PASSED" if not material_exists else "FAILED"
            self.stdout.write(self.style.SUCCESS(f"Test 2 result: {test2_result}"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Test 2 ERROR: {str(e)}"))
        
        self.stdout.write(self.style.SUCCESS('Supabase storage test completed'))