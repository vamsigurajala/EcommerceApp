# application/utils/auth.py
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from django.conf import settings

def get_user_from_request(request):
    token = request.COOKIES.get('jwt')
    if not token:
        return None, True
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        from application.models import User
        user = User.objects.filter(user_id=payload.get('user_id')).first()
        return (user, False) if user else (None, True)
    except ExpiredSignatureError:
        return None, True
    except InvalidTokenError:
        return None, True
