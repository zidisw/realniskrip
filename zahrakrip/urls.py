"""
Melakukan navigasi terhadap alamat-alamat website. 
Akan memberikan alamat/link pada website

"""

from django.contrib import admin
from django.urls import path, include
from posting.views import * 
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('generate_keys/', generate_keys, name='generate_keys'), 
    path('posting/', include('posting.urls')),
    path('posting/result_enkrip/<int:encrypted_file_id>/',result_enkrip, name='result_enkrip'),
    path('posting/decryption_result/<int:decrypted_file_id>/', decryption_result, name='decryption_result'),
    path('posting/split_secret_sharing/<int:encrypted_file_id>/', split_secret_sharing, name='split_secret_sharing'),
    path('posting/upload_shares_to_cloud/<int:encrypted_file_id>/',upload_shares_to_cloud, name='upload_shares_to_cloud'),
    path('posting/reconstruct_secret_sharing/', reconstruct_secret_sharing, name='reconstruct_secret_sharing'),
    path('posting/result_reconstruct/', result_reconstruct, name='result_reconstruct'),
    path('posting/download_reconstructed/', download_reconstructed, name='download_reconstructed'),
    path('posting/oauth2callback/', oauth2callback, name='oauth2callback'),
    # path('posting/dropbox_callback/', dropbox_callback, name='dropbox_callback'),
    # path('posting/test-session/', test_session, name='test_session'),
    # path('google-drive-authenticate/ <int:encrypted_file_id>/', google_drive_authenticate, name='google_drive_authenticate'),
    # path('dropbox-authenticate/<int:encrypted_file_id>/', dropbox_authenticate, name='dropbox_authenticate'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)