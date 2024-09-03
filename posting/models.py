from django.db import models

class UploadedFile(models.Model):
    plainfile = models.FileField(upload_to='plainfiles/')
    keyfile = models.FileField(upload_to='keys/', null=True, blank=True)
    encryptedfile = models.FileField(upload_to='encryptedfiles/', null=True, blank=True)
    decryptedfile = models.FileField(upload_to='decryptedfiles/', null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    large_part = models.FileField(upload_to='largeparts/', null=True, blank=True) 
