from django.core.files.base import ContentFile
from core.models import Materials

# Create a test file
test_file = ContentFile(b"Test content", name="test.txt")

# Create a new Materials object
material = Materials(title="Test Document")
material.file_path.save("test.txt", test_file)
material.save()

# Verify the URL works
print(material.file_path.url)