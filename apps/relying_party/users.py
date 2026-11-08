"""The local user for the claims of an ID token."""
from django.contrib.auth import get_user_model

from .errors import ProtocolError


class RolesMissing(ProtocolError):
    """The identity provider checks roles and the user has none. The view sends the user to extend_access_uri."""

    def __init__(self, extend_access_uri):
        super().__init__('access_denied', "Sorry, you don't have access to this application.")
        self.extend_access_uri = extend_access_uri


def get_roles(client, claims):
    if not client.roles_claim:
        return set()
    value = claims.get(client.roles_claim)
    if isinstance(value, str):
        return set(value.split())
    if isinstance(value, list):
        return {str(role) for role in value}
    return set()


def update_user(client, claims):
    """Creates or updates the user identified by identity provider and sub (OpenID Connect Core 5.7)."""
    identity_provider = client.identity_provider
    sub = claims.get('sub')
    # Core 2: sub is at most 255 ASCII characters, longer values would not fit into the database.
    if not isinstance(sub, str) or not sub or len(sub) > 255:
        raise ProtocolError('invalid_id_token', 'The sub of the ID token is not a string of 1 to 255 characters.')
    roles = get_roles(client, claims)
    if identity_provider.check_roles and not roles:
        raise RolesMissing(identity_provider.extend_access_uri)

    user, created = get_user_model().objects.get_or_create(
        identity_provider=identity_provider, sub=sub, defaults={'username': f'{identity_provider.pk}:{sub}'})
    if not user.is_active:
        # Django would log the user in and then treat every request as anonymous, without telling why.
        raise ProtocolError('access_denied', 'Your account is deactivated in this demo.')
    if created:
        user.set_unusable_password()  # the user only logs in at the identity provider
    user.first_name = str(claims.get('given_name', ''))[:150]
    user.last_name = str(claims.get('family_name', ''))[:150]
    user.email = str(claims.get('email', ''))[:254]

    # The roles only decide about the admin access if the client names roles for it. Otherwise the status set by hand
    # in the admin stays.
    staff_roles = set(client.staff_roles.split())
    superuser_roles = set(client.superuser_roles.split())
    if staff_roles or superuser_roles:
        user.is_superuser = bool(roles & superuser_roles)
        user.is_staff = user.is_superuser or bool(roles & staff_roles)
    user.save()
    return user
