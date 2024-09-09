import os
import base64
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, FileResponse, JsonResponse
from .forms import UploadFileForm
from .models import UploadedFile
from .utils import aes_decrypt, decrypt_file_util, encrypt_file_util,  rsa_encrypt, generate_rsa_keys, read_file, write_file, save_rsa_keys_to_file, adjust_key_length, prepare_aes_key, rsa_decrypt, prepare_rsa_key, process_shamir_secret_sharing, write_binary_file, read_binary_file, recover_secret, join_data
import logging
from django.core.files import File
from pydrive.auth import GoogleAuth
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from msal import ConfidentialClientApplication
import dropbox
import requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google_auth_oauthlib.flow import InstalledAppFlow
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
import time
from google.auth.transport.requests import Request
import io

logger = logging.getLogger(__name__)

from .utils import generate_rsa_keys

def generate_keys(request):
    if request.method == 'POST':
        # Generate RSA keys
        public_key, private_key = generate_rsa_keys('posting/primes-to-100k.txt')
        
        # Define the path where the keys will be stored
        public_key_path = os.path.join('public_keys.txt')
        private_key_path = os.path.join('private_keys.txt')
        
        # Save the keys to files
        save_rsa_keys_to_file(public_key, private_key, public_key_path, private_key_path)
        
        return HttpResponse("RSA keys successfully generated and stored.")
    else:
        return render(request, 'posting/generate_keys.html')

def encrypt_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['plainfile']
            key_file = request.FILES['keyfile']
            key = prepare_aes_key(key_file)
            if key is None:
                return HttpResponse("Invalid encryption key length.", status=400)

            try:
                # Simpan file asli
                uploaded_instance = UploadedFile(plainfile=uploaded_file)
                uploaded_instance.save()

                # Enkripsi file menggunakan AES
                file_path = os.path.join(settings.MEDIA_ROOT, uploaded_instance.plainfile.name)
                encrypted_file_path = encrypt_file_util(file_path, key)
                encrypted_file_name = os.path.basename(encrypted_file_path)
                with open(encrypted_file_path, 'rb') as f:
                    uploaded_instance.encryptedfile.save(encrypted_file_name, File(f))

                # Enkripsi kunci menggunakan RSA
                public_key, private_key = generate_rsa_keys('posting/primes-to-100k.txt')
                encrypted_key = rsa_encrypt(public_key, key)
                encrypted_key_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_aes_key.txt')
                with open(encrypted_key_path, 'w') as f:
                    for block in encrypted_key:
                        f.write(f"{block}\n")

                # Simpan kunci RSA ke file (opsional, sesuai kebutuhan)
                save_rsa_keys_to_file(public_key, private_key, 'public_key.txt', 'private_key.txt')

                uploaded_instance.save()
                return redirect('result_enkrip', encrypted_file_id=uploaded_instance.id)
            except Exception as e:
                logger.error(f"Error during encryption: {e}")
                return HttpResponse("Encryption failed.", status=500)
        else:
            logger.error("Form is not valid")
            return HttpResponse("Form is not valid", status=400)
    else:
        form = UploadFileForm()
        return render(request, 'posting/encrypt.html', {'form': form})
    
def decrypt_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            encrypted_file = request.FILES['plainfile']
            private_key_file = request.FILES['keyfile']
            private_key = prepare_rsa_key(private_key_file)

            if private_key is None:
                return HttpResponse("Invalid private key.", status=400)

            try:
                 # Catat waktu mulai dekripsi
                start_time = time.perf_counter()
                logger.info(f"Start time: {start_time}")  # Tambahkan log untuk waktu mulai
                
                # Simpan file terenkripsi
                uploaded_instance = UploadedFile(encryptedfile=encrypted_file)
                uploaded_instance.save()

                file_path = os.path.join(settings.MEDIA_ROOT, uploaded_instance.encryptedfile.name)
                logger.info(f"Decrypting file at {file_path}")

                # Dekripsi kunci AES menggunakan kunci privat RSA
                encrypted_key_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_aes_key.txt')
                with open(encrypted_key_path, 'r') as f:
                    encrypted_key = [int(line.strip()) for line in f.readlines()]
                aes_key = rsa_decrypt(private_key, encrypted_key)

                logger.info(f"Decrypted AES key length: {len(aes_key)} bytes, Key: {aes_key.hex()}")

                # Memastikan panjang kunci tepat 16 bytes
                if len(aes_key) != 16:
                    logger.error("Decryption key must be exactly 16 bytes long")
                    return HttpResponse("Invalid AES key length after decryption.", status=400)

                # Dekripsi file menggunakan AES
                decrypted_file_path = decrypt_file_util(file_path, aes_key)
                
                # Catat waktu selesai dekripsi
                end_time = time.perf_counter()
                logger.info(f"End time: {end_time}")  # Tambahkan log untuk waktu selesai
                decryption_duration = end_time - start_time  # Durasi proses dekripsi dalam detik
                logger.info(f"Decryption duration: {decryption_duration} seconds")  # Log durasi dekripsi
                
                # Ubah nama file hasil dekripsi menjadi .docx
                decrypted_file_name = os.path.basename(file_path).rsplit('.', 1)[0] + '.docx'
                decrypted_file_save_path = os.path.join(os.path.dirname(decrypted_file_path), decrypted_file_name)
                os.rename(decrypted_file_path, decrypted_file_save_path)

                with open(decrypted_file_save_path, 'rb') as f:
                    uploaded_instance.decryptedfile.save(decrypted_file_name, File(f))

                uploaded_instance.save()
                # Simpan durasi dekripsi ke sesi
                request.session['decryption_duration'] = decryption_duration

                return redirect('decryption_result', decrypted_file_id=uploaded_instance.id)
            except Exception as e:
                logger.error(f"Error during decryption: {e}")
                return HttpResponse("Decryption failed.", status=500)
        else:
            return HttpResponse("Form is not valid", status=400)
    else:
        form = UploadFileForm()
        return render(request, 'posting/decrypt.html', {'form': form})

def result_enkrip(request, encrypted_file_id):
    encrypted_file = get_object_or_404(UploadedFile, id=encrypted_file_id)
    return render(request, 'posting/result_enkrip.html', {'encrypted_file': encrypted_file})

def decryption_result(request, decrypted_file_id):
    decrypted_file = get_object_or_404(UploadedFile, id=decrypted_file_id)
    decryption_duration = request.session.get('decryption_duration')  # Ambil durasi dekripsi dari sesi
    
    context = {
        'decrypted_file': decrypted_file,
        'decryption_duration': decryption_duration  # Kirim durasi ke context
    }
    return render(request, 'posting/result_decrypt.html', context)

# Tambahkan fungsi split_secret_sharing
def split_secret_sharing(request, encrypted_file_id):
    encrypted_file = get_object_or_404(UploadedFile, id=encrypted_file_id)
    file_path = os.path.join(settings.MEDIA_ROOT, encrypted_file.encryptedfile.name)
    
    try:
        # Proses Shamir's Secret Sharing pada bagian kecil
        shares, large_part = process_shamir_secret_sharing(file_path)
        
        # Simpan bagian besar ke file dengan nama .enc
        large_part_path = os.path.join(settings.MEDIA_ROOT, 'largeparts', 'large_part.enc')
        os.makedirs(os.path.dirname(large_part_path), exist_ok=True)  # Buat direktori jika belum ada
        write_binary_file(large_part_path, large_part)

        # Simpan bagian besar ke model
        with open(large_part_path, 'rb') as f:
            encrypted_file.large_part.save('large_part.enc', File(f))
        
        # Pastikan direktori 'shares' ada
        shares_dir = os.path.join(settings.MEDIA_ROOT, 'shares')
        os.makedirs(shares_dir, exist_ok=True)

        # Simpan shares ke file
        shares_file_paths = []
        for i, share in enumerate(shares):
            share_path = os.path.join(shares_dir, f'share_{i + 1}.txt')
            with open(share_path, 'w') as f:
                f.write(str(share))
            shares_file_paths.append(default_storage.url(f'shares/share_{i + 1}.txt'))
        
        # Simpan shares ke file
        
        encrypted_file.save()
        
        context = {
            'shares_file_paths': shares_file_paths,
            'large_part_url': encrypted_file.large_part.url,
            'encrypted_file_id': encrypted_file.id,  # Pastikan ID file terenkripsi tersedia
            'encrypted_file': encrypted_file,
        }

        return render(request, 'posting/result_shamir.html', context)
    except Exception as e:
        logger.error(f"Error during Shamir's Secret Sharing: {e}")
        return HttpResponse("Shamir's Secret Sharing failed.", status=500)


logger = logging.getLogger(__name__)


def upload_shares_to_cloud(request, encrypted_file_id):
    # Ensure the request is a POST request
    if request.method != 'POST':
        return HttpResponse("Invalid request method. POST required.", status=400)

    # Ensure Google Drive credentials are in the session
    if 'google_drive_credentials' not in request.session:
        return redirect('google_drive_authenticate', encrypted_file_id=encrypted_file_id)

    # Ensure Dropbox access token is set
    if not settings.DROPBOX_ACCESS_TOKEN:
        return HttpResponse("Dropbox access token is missing.", status=400)

    # Ensure OneDrive access token is in the session
    if 'onedrive_access_token' not in request.session:
        return redirect('onedrive_authenticate', encrypted_file_id=encrypted_file_id)

    # Now retrieve the file and its shares for upload
    encrypted_file = get_object_or_404(UploadedFile, id=encrypted_file_id)
    shares_file_paths = request.POST.getlist('shares_file_paths')

    if not shares_file_paths:
        return HttpResponse("No shares provided for upload.", status=400)

    try:
        # Prepare full file paths for the shares
        full_shares_file_paths = [
            os.path.join(settings.MEDIA_ROOT, os.path.relpath(share_file_path, '/media/'))
            for share_file_path in shares_file_paths
        ]

        # Google Drive Upload
        credentials = Credentials(**request.session['google_drive_credentials'])
        drive_service = build('drive', 'v3', credentials=credentials)
        with open(full_shares_file_paths[0], 'rb') as share_file:
            file_metadata = {'name': os.path.basename(full_shares_file_paths[0])}
            media = MediaFileUpload(share_file.name)
            drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()

        # Dropbox Upload
        dbx = dropbox.Dropbox(settings.DROPBOX_ACCESS_TOKEN)
        with open(full_shares_file_paths[1], 'rb') as share_file:
            dbx.files_upload(share_file.read(), '/' + os.path.basename(full_shares_file_paths[1]), mute=True)

        # OneDrive Upload
        access_token = request.session.get('onedrive_access_token')
        for i in range(2, len(full_shares_file_paths)):
            one_drive_upload_url = f"https://graph.microsoft.com/v1.0/me/drive/root:/{os.path.basename(full_shares_file_paths[i])}:/content"
            with open(full_shares_file_paths[i], 'rb') as share_file:
                file_content = share_file.read()

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/octet-stream'
            }
            response = requests.put(one_drive_upload_url, headers=headers, data=file_content)

            if response.status_code != 201:
                logger.error(f"Failed to upload to OneDrive: {response.text}")
                return HttpResponse(f"Failed to upload to OneDrive: {response.text}", status=500)

        logger.info("All shares successfully uploaded to cloud services.")
        return render(request, 'posting/upload_success.html')

    except Exception as e:
        logger.error(f"Uploading shares to cloud failed: {str(e)}")
        return HttpResponse(f"Uploading shares to cloud failed: {str(e)}", status=500)

    
# Google Drive Authentication
def google_drive_authenticate(request, encrypted_file_id):
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
    credentials = flow.run_local_server(port=8080)
    request.session['google_drive_credentials'] = credentials_to_dict(credentials)
    return redirect('upload_shares_to_cloud', encrypted_file_id=encrypted_file_id)

def dropbox_authenticate(request):
    auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(
        settings.APP_KEY,
        settings.APP_SECRET,
        token_access_type='offline',  # This ensures long-lived access tokens
        scope=['files.content.write', 'files.content.read']  # Specify required scopes
    )
    authorize_url = auth_flow.start()
    return redirect(authorize_url)


# Handle Dropbox callback (if needed)
def dropbox_callback(request):
    auth_code = request.GET.get('code')
    if not auth_code:
        return HttpResponse("Authorization code is missing.", status=400)

    auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(settings.APP_KEY, settings.APP_SECRET)
    try:
        access_token, user_id = auth_flow.finish(auth_code)
        request.session['dropbox_access_token'] = access_token
        return redirect('upload_shares_to_cloud', encrypted_file_id=request.session.get('encrypted_file_id'))
    except Exception as e:
        logger.error(f"Error getting Dropbox access token: {e}")
        return HttpResponse("Failed to authenticate with Dropbox.", status=500)

def clear_dropbox_token(request):
    if 'dropbox_access_token' in request.session:
        del request.session['dropbox_access_token']
    return redirect('dropbox_authenticate')

def onedrive_authenticate(request, encrypted_file_id):
    try:
        # Buat instance aplikasi klien rahasia menggunakan MSAL
        app = ConfidentialClientApplication(
            client_id=settings.ONEDRIVE_CLIENT_ID,
            authority=settings.ONEDRIVE_AUTHORITY,
            client_credential=settings.ONEDRIVE_CLIENT_SECRET
        )

        # URL otorisasi OneDrive
        auth_url = app.get_authorization_request_url(
            scopes=settings.ONEDRIVE_SCOPES,
            redirect_uri=settings.ONEDRIVE_REDIRECT_URI
        )

        # Simpan encrypted_file_id dalam sesi
        request.session['encrypted_file_id'] = encrypted_file_id

        # Paksa Django untuk menyimpan sesi
        request.session.save()

        # Logging untuk memastikan data sesi tersimpan dengan benar
        logger.info(f"Session data before redirecting to OneDrive: {request.session.items()}")

        # Tambahkan encrypted_file_id ke URL sebagai state untuk memastikan dikembalikan setelah callback
        return redirect(f'{auth_url}&state={encrypted_file_id}')
    
    except Exception as e:
        logger.error(f"Error during OneDrive authentication: {str(e)}")
        return HttpResponse("Failed to initiate OneDrive authentication.", status=500)


def onedrive_callback(request):
    logger.info("OneDrive callback initiated")

    # Dapatkan kode otorisasi dari parameter URL
    code = request.GET.get('code')
    encrypted_file_id = request.GET.get('state') or request.session.get('encrypted_file_id')

    if not code or not encrypted_file_id:
        return HttpResponse("Authorization code or file ID missing.", status=400)

    try:
        # Tukar kode otorisasi dengan token
        app = ConfidentialClientApplication(
            client_id=settings.ONEDRIVE_CLIENT_ID,
            authority=settings.ONEDRIVE_AUTHORITY,
            client_credential=settings.ONEDRIVE_CLIENT_SECRET
        )
        
        result = app.acquire_token_by_authorization_code(
            code,
            scopes=settings.ONEDRIVE_SCOPES,
            redirect_uri=settings.ONEDRIVE_REDIRECT_URI
        )

        if 'access_token' in result:
            # Simpan access token di session
            request.session['onedrive_access_token'] = result['access_token']
            return redirect('split_secret_sharing', encrypted_file_id=encrypted_file_id)
        else:
            error_msg = result.get('error_description', 'Unknown error during token exchange')
            return HttpResponse(f"Failed to exchange authorization code: {error_msg}", status=400)

    except Exception as e:
        logger.error(f"Error during token exchange: {str(e)}")
        return HttpResponse(f"Error during token exchange: {str(e)}", status=500)


# Convert Google credentials to a dictionary
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


#AMBIL FILE RECONSTRUCT 
def fetch_from_google_drive_ajax(request):
    if not hasattr(request, 'session'):
        return JsonResponse({'error': 'Session not available'}, status=400)

    google_drive_credentials = request.session.get('google_drive_credentials')
    if not google_drive_credentials:
        return JsonResponse({'error': 'Google Drive credentials not found'}, status=400)

    credentials = Credentials(**google_drive_credentials)
    service = build('drive', 'v3', credentials=credentials)

    # Ambil file dari Google Drive
    results = service.files().list(pageSize=10, fields="files(id, name)").execute()
    files = results.get('files', [])

    return JsonResponse({'files': files})


def fetch_from_dropbox_ajax(request):
    # Ambil token akses langsung dari settings.py
    dropbox_access_token = settings.DROPBOX_ACCESS_TOKEN

    if not dropbox_access_token:
        return JsonResponse({'error': 'Dropbox access token is missing'}, status=400)

    # Gunakan token untuk mengakses Dropbox
    dbx = dropbox.Dropbox(dropbox_access_token)
    try:
        files = dbx.files_list_folder('').entries
        file_list = [{'name': file.name} for file in files]
        return JsonResponse({'files': file_list})
    except dropbox.exceptions.ApiError as error:
        return JsonResponse({'error': f'Failed to fetch files from Dropbox: {error}'}, status=400)

def fetch_from_onedrive_ajax(request):
    onedrive_token_info = request.session.get('onedrive_token')
    if not onedrive_token_info:
        return JsonResponse({'error': 'OneDrive token not found'}, status=401)

    # Periksa apakah token sudah kadaluwarsa
    expires_at = onedrive_token_info.get('expires_at')
    access_token = onedrive_token_info.get('access_token')

    if not access_token or (expires_at and expires_at < time.time()):
        # Jika token expired atau tidak ada, redirect untuk otentikasi ulang
        return redirect('onedrive_authenticate', encrypted_file_id=request.session.get('encrypted_file_id'))

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    # Ambil file dari OneDrive
    response = requests.get('https://graph.microsoft.com/v1.0/me/drive/root/children', headers=headers)
    
    if response.status_code == 200:
        files = response.json().get('value', [])
        return JsonResponse({'files': [{'name': file['name'], 'id': file['id']} for file in files]})
    else:
        return JsonResponse({'error': 'Failed to fetch files from OneDrive'}, status=response.status_code)

    
def download_from_google_drive(request, file_id):
    google_drive_credentials = request.session.get('google_drive_credentials')
    if not google_drive_credentials:
        return JsonResponse({'error': 'Google Drive credentials not found'}, status=400)

    credentials = Credentials(**google_drive_credentials)
    service = build('drive', 'v3', credentials=credentials)

    # Unduh file dari Google Drive
    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)

    done = False
    while not done:
        status, done = downloader.next_chunk()

    fh.seek(0)
    file_metadata = service.files().get(fileId=file_id, fields='name').execute()
    file_name = file_metadata.get('name')

    response = HttpResponse(fh.read(), content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{file_name}"'
    return response

def download_from_dropbox(request, file_name):
    dropbox_access_token = settings.DROPBOX_ACCESS_TOKEN

    if not dropbox_access_token:
        return JsonResponse({'error': 'Dropbox access token is missing'}, status=400)

    dbx = dropbox.Dropbox(dropbox_access_token)
    try:
        # Download file dari Dropbox
        metadata, res = dbx.files_download(f'/{file_name}')
        response = HttpResponse(res.content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response
    except dropbox.exceptions.ApiError as error:
        return JsonResponse({'error': f'Failed to download file from Dropbox: {error}'}, status=400)

def download_from_onedrive(request, file_id):
    onedrive_token_info = request.session.get('onedrive_token')
    if not onedrive_token_info:
        return JsonResponse({'error': 'OneDrive token not found'}, status=400)

    access_token = onedrive_token_info.get('access_token')
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    # Unduh file dari OneDrive
    response = requests.get(f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/content', headers=headers)
    
    if response.status_code == 200:
        file_name = response.headers.get('Content-Disposition').split('filename=')[1].strip('"')
        return HttpResponse(response.content, content_type='application/octet-stream')
    else:
        return JsonResponse({'error': 'Failed to download file from OneDrive'}, status=response.status_code)

def upload_from_google_drive_to_system(request, file_name):
    # Cek apakah request memiliki session
    if not hasattr(request, 'session'):
        return JsonResponse({'error': 'Session not available'}, status=400)

    google_drive_credentials = request.session.get('google_drive_credentials')
    if not google_drive_credentials:
        return JsonResponse({'error': 'Google Drive credentials not found'}, status=400)

    try:
        credentials = Credentials(**google_drive_credentials)

        # Periksa apakah token expired dan refresh jika perlu
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            request.session['google_drive_credentials'] = credentials_to_dict(credentials)

        service = build('drive', 'v3', credentials=credentials)

        # Pastikan objek request untuk get_media adalah milik google API, bukan Django HttpRequest
        drive_request = service.files().get_media(fileId=file_name)  # Gunakan variabel 'drive_request'
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, drive_request)  # Menggunakan 'drive_request' bukan Django request

        done = False
        while not done:
            status, done = downloader.next_chunk()

        # Simpan file ke sistem
        file_path = f'google_drive_uploads/{file_name}.txt'
        saved_file = default_storage.save(file_path, ContentFile(fh.getvalue()))

        # Tambahkan file yang diunggah ke session
        if 'uploaded_files' not in request.session:
            request.session['uploaded_files'] = []
        uploaded_files = request.session['uploaded_files']
        uploaded_files.append(saved_file)
        request.session['uploaded_files'] = uploaded_files

        return JsonResponse({'message': 'File successfully uploaded', 'file_path': saved_file})

    except Exception as e:
        print(f"Error: {e}")
        return JsonResponse({'error': f'Failed to upload file from Google Drive: {e}'}, status=400)


def upload_from_dropbox_to_system(request, file_name):
    dropbox_access_token = settings.DROPBOX_ACCESS_TOKEN

    if not dropbox_access_token:
        return JsonResponse({'error': 'Dropbox access token is missing'}, status=400)

    dbx = dropbox.Dropbox(dropbox_access_token)
    try:
        # Download file dari Dropbox
        metadata, res = dbx.files_download(f'/{file_name}')
        
        # Simpan file ke sistem (misalnya direktori media)
        file_path = f'dropbox_uploads/{file_name}'
        saved_file = default_storage.save(file_path, ContentFile(res.content))
        
        # Tambahkan nama file yang diunggah ke session
        if 'uploaded_files' not in request.session:
            request.session['uploaded_files'] = []
        
        uploaded_files = request.session['uploaded_files']
        uploaded_files.append(saved_file)
        request.session['uploaded_files'] = uploaded_files
        
        # Return file path atau status sukses
        return JsonResponse({'message': 'File successfully uploaded', 'file_path': saved_file})
    except dropbox.exceptions.ApiError as error:
        return JsonResponse({'error': f'Failed to upload file from Dropbox: {error}'}, status=400)

def upload_from_onedrive_to_system(request, file_name):
    onedrive_token_info = request.session.get('onedrive_token')
    if not onedrive_token_info:
        return JsonResponse({'error': 'OneDrive token not found'}, status=400)

    access_token = onedrive_token_info.get('access_token')
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    try:
        # Download file dari OneDrive
        response = requests.get(f'https://graph.microsoft.com/v1.0/me/drive/items/{file_name}/content', headers=headers)
        
        if response.status_code == 200:
            # Simpan file ke sistem
            file_path = f'onedrive_uploads/{file_name}.txt'
            saved_file = default_storage.save(file_path, ContentFile(response.content))

            # Tambahkan ke session
            if 'uploaded_files' not in request.session:
                request.session['uploaded_files'] = []
            uploaded_files = request.session['uploaded_files']
            uploaded_files.append(saved_file)
            request.session['uploaded_files'] = uploaded_files

            return JsonResponse({'message': 'File successfully uploaded', 'file_path': saved_file})
        else:
            return JsonResponse({'error': 'Failed to download file from OneDrive'}, status=response.status_code)

    except Exception as e:
        return JsonResponse({'error': f'Failed to upload file from OneDrive: {e}'}, status=400)
  

def reconstruct_secret_sharing(request):
    if request.method == 'POST':
        shares_files = request.FILES.getlist('shares_files')
        large_part_file = request.FILES['large_part_file']
        
        if len(shares_files) < 2:
            return HttpResponse("Insufficient shares provided. You need to upload at least 2 shares.", status=400)
        
        shares = []
        for file in shares_files:
            share_content = file.read().decode('utf-8').strip()
            share = tuple(map(int, share_content[1:-1].split(',')))
            shares.append(share)

        try:
            # Catat waktu mulai rekonstruksi
            start_time = time.perf_counter()
            logger.info(f"Start time: {start_time}")  # Tambahkan log untuk waktu mulai
            
            # Rekonstruksi secret
            reconstructed_secret = recover_secret(shares)
            
            # Baca bagian besar dari file yang diunggah
            large_part = large_part_file.read()
            
            # Gabungkan bagian besar dan secret yang direkonstruksi
            reconstructed_data = join_data(reconstructed_secret.to_bytes(16, 'big'), large_part)
            
            # Catat waktu selesai rekonstruksi
            end_time = time.perf_counter()
            logger.info(f"End time: {end_time}")  # Tambahkan log untuk waktu selesai
            reconstruction_duration = end_time - start_time  # Durasi proses rekonstruksi dalam detik
            logger.info(f"Reconstruction duration: {reconstruction_duration} seconds")  # Tambahkan log untuk durasi
            
            # Simpan file hasil rekonstruksi
            reconstructed_file_path = os.path.join(settings.MEDIA_ROOT, 'reconstructed', 'reconstructed_file.enc')
            os.makedirs(os.path.dirname(reconstructed_file_path), exist_ok=True)
            write_binary_file(reconstructed_file_path, reconstructed_data)
            
            # Simpan path file yang direkonstruksi ke dalam sesi
            request.session['reconstructed_file_path'] = reconstructed_file_path
            request.session['reconstruction_duration'] = reconstruction_duration  # Simpan durasi ke session
            
            # Arahkan pengguna ke halaman hasil rekonstruksi
            return redirect('result_reconstruct')
        except Exception as e:
            logger.error(f"Error during secret reconstruction: {e}")
            return HttpResponse("Secret reconstruction failed.", status=500)
    else:
        return render(request, 'posting/reconstruct.html')
    
def result_reconstruct(request):
    reconstructed_file_path = request.session.get('reconstructed_file_path')
    reconstruction_duration = request.session.get('reconstruction_duration')  # Ambil durasi dari session
    if not reconstructed_file_path or not os.path.exists(reconstructed_file_path):
        return HttpResponse("Reconstructed file not found.", status=404)

    context = {
        'reconstructed_file_path': reconstructed_file_path,
        'reconstruction_duration': reconstruction_duration  # Tambahkan durasi ke context
    }
    return render(request, 'posting/result_reconstruct.html', context)

def download_reconstructed(request):
    reconstructed_file_path = request.session.get('reconstructed_file_path')
    if not reconstructed_file_path or not os.path.exists(reconstructed_file_path):
        return HttpResponse("Reconstructed file not found.", status=404)

    response = FileResponse(open(reconstructed_file_path, 'rb'))
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(reconstructed_file_path)}"'
    return response

#UPLOAD CLOUD
def oauth2callback(request):
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()
    return redirect('home')  # Ubah sesuai kebutuhan Anda


#FUNGSI VIEWS
def home(request):
    return render(request, 'posting/home.html')