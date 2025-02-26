from django.conf import settings
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from supabase import create_client, Client
import os
import tempfile
from django.core.files.base import ContentFile

@deconstructible
class SupabaseStorage(Storage):
    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL
        self.supabase_key = settings.SUPABASE_KEY
        self.bucket_name = settings.SUPABASE_BUCKET_NAME
        self.supabase: Client = create_client(self.supabase_url, self.supabase_key)
    
    def _save(self, name, content):
        # Ensure the file pointer is at the beginning
        content.seek(0)
        content_file = content.read()
        
        # Upload to Supabase
        self.supabase.storage.from_(self.bucket_name).upload(name, content_file)
        return name
    
    def _open(self, name, mode='rb'):
        # Download the file from Supabase
        try:
            data = self.supabase.storage.from_(self.bucket_name).download(name)
            return ContentFile(data)
        except Exception as e:
            raise FileNotFoundError(f"File {name} does not exist in Supabase storage")
    
    def exists(self, name):
        try:
            # List objects with this name to check if it exists
            files = self.supabase.storage.from_(self.bucket_name).list(path=os.path.dirname(name))
            base_name = os.path.basename(name)
            
            # Check if any file with the same name exists
            for file in files:
                if file.get('name') == base_name:
                    return True
                    
            return False
        except:
            return False
    
    def url(self, name):
        # Get the public URL for a file
        return self.supabase.storage.from_(self.bucket_name).get_public_url(name)
    
    def size(self, name):
        # This is tricky with Supabase - we'll need to download file info first
        try:
            # List the files to get metadata
            files = self.supabase.storage.from_(self.bucket_name).list(path=os.path.dirname(name))
            base_name = os.path.basename(name)
            
            # Find the file with matching name
            for file in files:
                if file.get('name') == base_name and 'metadata' in file:
                    return file.get('metadata', {}).get('size', 0)
            
            # Fallback: download the file and get its size
            data = self.supabase.storage.from_(self.bucket_name).download(name)
            return len(data) if data else 0
        except:
            return 0
    
    def delete(self, name):
        try:
            self.supabase.storage.from_(self.bucket_name).remove([name])
            return True
        except:
            return False
            
    def get_accessed_time(self, name):
        # Supabase doesn't provide access time
        from datetime import datetime
        return datetime.now()
        
    def get_created_time(self, name):
        # Supabase doesn't provide creation time in a standard way
        from datetime import datetime
        return datetime.now()
        
    def get_modified_time(self, name):
        # Supabase doesn't provide modification time in a standard way
        from datetime import datetime
        return datetime.now()