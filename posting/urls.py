from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('encrypt/', views.encrypt_file, name='encrypt_file'),
    path('decrypt/', views.decrypt_file, name='decrypt_file'),
    path('google-drive-authenticate/<int:encrypted_file_id>/', views.google_drive_authenticate, name='google_drive_authenticate'),
    path('dropbox-callback/', views.dropbox_callback, name='dropbox_callback'),
    path('onedrive-authenticate/<int:encrypted_file_id>/', views.onedrive_authenticate, name='onedrive_authenticate'),
    path('onedrive-callback/', views.onedrive_callback, name='onedrive_callback'),  # Add this line
    path('fetch_from_google_drive_ajax/', views.fetch_from_google_drive_ajax, name='fetch_from_google_drive_ajax'),
    path('fetch_from_dropbox_ajax/', views.fetch_from_dropbox_ajax, name='fetch_from_dropbox_ajax'),
    path('fetch_from_onedrive_ajax/', views.fetch_from_onedrive_ajax, name='fetch_from_onedrive_ajax'),
    path('download_from_google_drive/<str:file_id>/', views.download_from_google_drive, name='download_from_google_drive'),
    path('download_from_dropbox/<str:file_name>/', views.download_from_dropbox, name='download_from_dropbox'),
    path('download_from_onedrive/<str:file_id>/', views.download_from_onedrive, name='download_from_onedrive'),
    path('upload_from_dropbox_to_system/<str:file_name>/', views.upload_from_dropbox_to_system, name='upload_from_dropbox_to_system'),
    path('upload_from_google_drive_to_system/<str:file_name>/', views.upload_from_google_drive_to_system, name='upload_from_google_drive_to_system'),
    path('upload_from_onedrive_to_system/<str:file_name>/', views.upload_from_onedrive_to_system, name='upload_from_onedrive_to_system'),
    path('reconstruct_secret_sharing/', views.reconstruct_secret_sharing, name='reconstruct_secret_sharing'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)