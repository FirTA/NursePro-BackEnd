from django.conf import settings
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from supabase import create_client, Client
import os

@deconstructible
class SupabaseStorage(Storage):
    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL
        self.supabase_key = settings.SUPABASE_KEY
        self.bucket_name = settings.SUPABASE_BUCKET_NAME
        self.supabase: Client = create_client(self.supabase_url, self.supabase_key)

    def _save(self, name, content):
        content_file = content.file.read()
        self.supabase.storage.from_(self.bucket_name).upload(name, content_file)
        return name

    def _open(self, name, mode='rb'):
        # This method is required but not used directly in this implementation
        pass

    def exists(self, name):
        try:
            self.supabase.storage.from_(self.bucket_name).download(name)
            return True
        except:
            return False

    def url(self, name):
        # Get the public URL for a file
        return f"{self.supabase_url}/storage/v1/object/public/{self.bucket_name}/{name}"