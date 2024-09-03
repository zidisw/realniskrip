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
    path('upload_shares_to_cloud/<int:encrypted_file_id>/', views.upload_shares_to_cloud, name='upload_shares_to_cloud'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
