from django.utils import timezone
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from jwt.exceptions import ExpiredSignatureError
from django.contrib.auth import get_user_model
from django.conf import settings


class JWTTokenExpirationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()
        
    def __call__(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
            try:
                # Try to get user from token using JWT authentication
                validated_token = self.jwt_auth.get_validated_token(token)
                user = self.jwt_auth.get_user(validated_token)
                
                # if we get here, token is valid
                # print('token is valid')
                return self.get_response(request)
            
            except (TokenError, InvalidToken):
                # Token is invalid or expired
                try:
                    # Manually decode the token without validation to get user_id
                    decoded_token = AccessToken(token, verify=False)
                    user_id = decoded_token.payload.get('user_id')
                    
                    if user_id :
                        User = get_user_model()
                        
                        try:
                            user = User.objects.get(id= user_id)
                            user.is_login = False
                            user.save()
                            
                        except User.DoesNotExist:
                            pass
                except Exception:
                    pass
        return self.get_response(request)