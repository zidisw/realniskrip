from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('encrypt/', views.encrypt_file, name='encrypt_file'),
    path('decrypt/', views.decrypt_file, name='decrypt_file'),
    path('google-drive-authenticate/<int:encrypted_file_id>/', views.google_drive_authenticate, name='google_drive_authenticate'),
    path('dropbox-authenticate/', views.dropbox_authenticate, name='dropbox_authenticate'),
    path('dropbox-callback/', views.dropbox_callback, name='dropbox_callback'),
    path('onedrive-authenticate/<int:encrypted_file_id>/', views.onedrive_authenticate, name='onedrive_authenticate'),
    path('onedrive-callback/', views.onedrive_callback, name='onedrive_callback'),  # Add this line
    path('upload_shares_to_cloud/<int:encrypted_file_id>/', views.upload_shares_to_cloud, name='upload_shares_to_cloud'),
    path('clear-session/', views.clear_session, name='clear_session'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
