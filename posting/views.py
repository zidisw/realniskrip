import os
import base64
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, FileResponse
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
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from django.shortcuts import redirect

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
                
                # Ubah nama file hasil dekripsi menjadi .docx
                decrypted_file_name = os.path.basename(file_path).rsplit('.', 1)[0] + '.docx'
                decrypted_file_save_path = os.path.join(os.path.dirname(decrypted_file_path), decrypted_file_name)
                os.rename(decrypted_file_path, decrypted_file_save_path)

                with open(decrypted_file_save_path, 'rb') as f:
                    uploaded_instance.decryptedfile.save(decrypted_file_name, File(f))

                uploaded_instance.save()
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
    return render(request, 'posting/result_decrypt.html', {'decrypted_file': decrypted_file})

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
            'encrypted_file': encrypted_file,
        }
        return render(request, 'posting/result_shamir.html', context)
    except Exception as e:
        logger.error(f"Error during Shamir's Secret Sharing: {e}")
        return HttpResponse("Shamir's Secret Sharing failed.", status=500)

def upload_shares_to_cloud(request, encrypted_file_id):
    if 'google_drive_credentials' not in request.session:
        return redirect('google_drive_authenticate', encrypted_file_id=encrypted_file_id)

    encrypted_file = get_object_or_404(UploadedFile, id=encrypted_file_id)
    shares_file_paths = request.POST.getlist('shares_file_paths')

    logger.info(f"Shares file paths: {shares_file_paths}")

    if len(shares_file_paths) < 1:
        logger.error(f"Expected at least 1 share, but got {len(shares_file_paths)}")
        return HttpResponse("No shares provided for upload.", status=400)

    try:
        full_shares_file_paths = [os.path.join(settings.MEDIA_ROOT, os.path.relpath(share_file_path, '/media/')) for share_file_path in shares_file_paths]
        logger.info(f"Full shares file paths: {full_shares_file_paths}")

        # Upload the first share to Google Drive
        credentials = Credentials(**request.session['google_drive_credentials'])
        drive_service = build('drive', 'v3', credentials=credentials)
        with open(full_shares_file_paths[0], 'rb') as share_file:
            file_metadata = {'name': os.path.basename(full_shares_file_paths[0])}
            media = MediaFileUpload(share_file.name)
            drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()

        # Attempt to render the success page
        try:
            return render(request, 'upload_success.html')
        except Exception as template_error:
            logger.error(f"Error rendering upload_success.html: {template_error}")
            return HttpResponse("There was an error rendering the success page.", status=500)

    except Exception as e:
        logger.error(f"Error during uploading to Google Drive: {e}")
        return HttpResponse(f"Uploading shares to Google Drive failed: {str(e)}", status=500)

def test_upload_success(request):
    try:
        return render(request, 'upload_success.html')
    except Exception as e:
        logger.error(f"Error rendering upload_success.html: {e}")
        return HttpResponse("There was an error rendering the success page.", status=500)


def google_drive_authenticate(request, encrypted_file_id):
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
    credentials = flow.run_local_server(port=8080)
    request.session['google_drive_credentials'] = credentials_to_dict(credentials)
    return redirect('upload_shares_to_cloud', encrypted_file_id=encrypted_file_id)


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def dropbox_authenticate(request):
    dbx = dropbox.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
    authorize_url = dbx.start()
    return redirect('split_secret_sharing')  # Arahkan ke URL untuk login Dropbox

def onedrive_authenticate(request):
    authority_url = 'https://login.microsoftonline.com/common'
    client_id = 'your_onedrive_client_id'
    client_secret = 'your_onedrive_client_secret'
    redirect_uri = 'http://localhost:8000/onedrive-callback/'

    app = ConfidentialClientApplication(
        client_id, authority=authority_url, client_credential=client_secret)
    flow = app.initiate_device_flow(scopes=["Files.ReadWrite.All"])
    request.session['onedrive_flow'] = flow
    return redirect(flow['split_secret_sharing'])  # Arahkan ke URL untuk login OneDrive

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
            # Rekonstruksi secret
            reconstructed_secret = recover_secret(shares)
            
            # Baca bagian besar dari file yang diunggah
            large_part = large_part_file.read()
            
            # Gabungkan bagian besar dan secret yang direkonstruksi
            reconstructed_data = join_data(reconstructed_secret.to_bytes(16, 'big'), large_part)
            
            # Simpan file hasil rekonstruksi
            reconstructed_file_path = os.path.join(settings.MEDIA_ROOT, 'reconstructed', 'reconstructed_file.enc')
            os.makedirs(os.path.dirname(reconstructed_file_path), exist_ok=True)
            write_binary_file(reconstructed_file_path, reconstructed_data)
            
            # Simpan path file yang direkonstruksi ke dalam sesi
            request.session['reconstructed_file_path'] = reconstructed_file_path
            
            # Arahkan pengguna ke halaman hasil rekonstruksi
            return redirect('result_reconstruct')
        except Exception as e:
            logger.error(f"Error during secret reconstruction: {e}")
            return HttpResponse("Secret reconstruction failed.", status=500)
    else:
        return render(request, 'posting/reconstruct.html')
    
def result_reconstruct(request):
    reconstructed_file_path = request.session.get('reconstructed_file_path')
    if not reconstructed_file_path or not os.path.exists(reconstructed_file_path):
        return HttpResponse("Reconstructed file not found.", status=404)

    context = {
        'reconstructed_file_path': reconstructed_file_path,
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
