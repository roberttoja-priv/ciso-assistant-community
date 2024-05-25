import os
from rest_framework.authentication import BaseAuthentication
from keycloak import KeycloakOpenID
from .models import User


class KeycloakAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Your authentication logic here using python-keycloak
        # Example:
        token = request.META.get("HTTP_AUTHORIZATION", "").split("Bearer ")[-1]
        keycloak = KeycloakOpenID(
            server_url=os.environ.get("KEYCLOAK_SERVER_URL"),
            client_id=os.environ.get("KEYCLOAK_CLIENT_ID"),
            client_secret_key=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
            realm_name="hr-dev",
        )

        try:
            user_info = keycloak.decode_token(token)

            # Create or retrieve Django user based on user_info
            # Example:
            user, created = User.objects.get_or_create(
                email=f"{user_info['preferred_username']}@example.com"
            )

            return user, None
        except Exception as e:
            return None
