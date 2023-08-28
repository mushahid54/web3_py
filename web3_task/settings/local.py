from .base import *

DEBUG = True


ALLOWED_HOSTS = ["*"]
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

STATIC_ROOT = str(BASE_DIR / 'staticfiles')

STATIC_URL = '/static/'

MEDIA_ROOT = str(BASE_DIR / 'media')

SITE_ADDRESS = 'http://localhost:8000'


