from django import forms
from .models import UploadedFile

class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['plainfile', 'keyfile']

class EncryptForm(forms.Form):
    plaintext = forms.CharField(widget=forms.Textarea, label='Plaintext')
    aes_key = forms.CharField(max_length=16, label='AES Key')
    rsa_keyfile = forms.FileField(label='RSA Key File')