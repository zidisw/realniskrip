import os

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-b#vy=-5c7k_vj*zi)7%5ay7v&(0xw2rgj_8yo4hsfw#7uxgo$)'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'posting',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'zahrakrip.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'posting', 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

OPTIONS = {
    'debug': True,
}

WSGI_APPLICATION = 'zahrakrip.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
}

DROPBOX_ACCESS_TOKEN = 'sl.B8w0zCxA6gW3mboJFE9AF9SpAka7EiTonGMddvlU60Oc0RlU3065d4PRWDXeI7zEzaCTybI2XO0gT4770FDrJ1-WX682ytH5i9M--ISu2i0gFI1ZhTbs7mWMXjROlfEtn5ihixuznL-F'

APP_KEY = '10b2v2rft2hnssf'
APP_SECRET = 'qhe65w88gokpfwa'

# settings.py

SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # Menggunakan DB untuk sesi
SESSION_COOKIE_SECURE = False  # Nonaktifkan hanya untuk testing di localhost
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# settings.py

ONEDRIVE_CLIENT_ID = '1adf0dfd-dc01-4b9b-a884-cbc9e1ca32d1'  # Replace with your Client ID
ONEDRIVE_CLIENT_SECRET = '19F8Q~6QLThWuHWIQiQBiY9YTRz7YRxdRWKSEcr4'  # Replace with your Client Secret
ONEDRIVE_REDIRECT_URI = 'http://localhost:8000/posting/onedrive-callback/'  # Replace with your Redirect URI
ONEDRIVE_AUTHORITY = 'https://login.microsoftonline.com/common'  # The authority URL for Microsoft accounts
ONEDRIVE_SCOPES = ['Files.ReadWrite.All']  # Scopes to request during OAuth
