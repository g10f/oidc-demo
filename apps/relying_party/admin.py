import requests
from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.urls import path, reverse
from django.utils.html import format_html

from .discovery import discovery_url, endpoints_of, fetch_discovery_document
from .errors import ProtocolError
from .models import ApiClient, Client, IdentityProvider, User


class AdminSite(admin.AdminSite):
    """The admin login page also offers the login with OpenID Connect (template admin/login.html)."""
    site_header = 'OIDC Demo administration'
    site_title = 'OIDC Demo'
    login_template = 'admin/oidc_login.html'


site = AdminSite()


class IssuerInput(forms.TextInput):
    """The issuer with a button that loads the discovery document into the form (static/js/admin-discovery.js)."""

    def render(self, name, value, attrs=None, renderer=None):
        return super().render(name, value, attrs, renderer) + format_html(
            '<div class="load-discovery"><button type="button" class="button default" id="load-discovery" '
            'data-url="{}">Load from discovery document</button> <span id="discovery-status"></span></div>',
            reverse('admin:relying_party_identityprovider_discovery'))


@admin.register(IdentityProvider, site=site)
class IdentityProviderAdmin(admin.ModelAdmin):
    class Media:
        css = {'all': ['css/admin.css']}
        js = ['js/admin-discovery.js']

    list_display = ('name', 'issuer', 'is_active', 'order')
    list_filter = ('is_active',)
    fieldsets = (
        ('Standard', {'fields': ('name', 'issuer', 'is_active', 'order', 'authorization_endpoint',
                                 'token_endpoint', 'userinfo_endpoint', 'jwks_uri')}),
        ('Optional', {'fields': ('home_uri', 'end_session_endpoint', 'device_authorization_endpoint',
                                 'check_session_iframe', 'require_iss_parameter', 'strong_acr_values', 'profile_uri',
                                 'picture_endpoint', 'user_navigation_uri')}),
        ('Legacy', {'classes': ('collapse',),
                    'fields': ('verify_tls', 'userinfo_token_in_query', 'check_roles', 'extend_access_uri')}),
    )

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        if db_field.name == 'issuer':
            kwargs['widget'] = IssuerInput(attrs={'class': 'vTextField'})
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    def get_urls(self):
        view = self.admin_site.admin_view(self.discovery_view)
        return [path('discovery/', view, name='relying_party_identityprovider_discovery')] + super().get_urls()

    def discovery_view(self, request):
        """
        Loads the discovery document of an issuer for the button and returns the values for the form as JSON. The
        request goes from this server, so the identity provider needs no CORS headers, and the issuer is checked
        here. Nothing is saved.
        """
        if not (self.has_add_permission(request) or self.has_change_permission(request)):
            raise PermissionDenied
        issuer = request.GET.get('issuer', '').strip()
        try:
            document = fetch_discovery_document(discovery_url(issuer),
                                                verify_tls=request.GET.get('verify_tls') != 'false')
        except ProtocolError as e:
            return JsonResponse({'error': e.description}, status=400)
        except requests.RequestException as e:
            return JsonResponse({'error': f'The discovery document can not be loaded: {type(e).__name__}'},
                                status=502)
        return JsonResponse({'fields': endpoints_of(document)})


@admin.register(Client, site=site)
class ClientAdmin(admin.ModelAdmin):
    class Media:
        css = {'all': ['css/admin.css']}
        js = ['js/copy.js']

    list_display = ('__str__', 'flow', 'client_id', 'is_active')
    list_filter = ('flow', 'is_active', 'identity_provider')
    fieldsets = (
        ('Standard', {'fields': ('identity_provider', 'name', 'is_active', 'flow', 'client_id', 'client_secret',
                                 'token_endpoint_auth_method', 'scope', 'id_token_signed_response_alg')}),
        ('Optional request parameters', {'fields': ('prompt', 'max_age', 'acr_values', 'ui_locales',
                                                    'claims_locales', 'claims', 'extra_authorization_params')}),
        ('Roles', {'fields': ('roles_claim', 'staff_roles', 'superuser_roles')}),
        ('Session and logout', {'fields': ('session_max_age', 'session_management', 'frontchannel_logout',
                                           'backchannel_logout',
                                           'backchannel_logout_session_required')}),
        ('Legacy', {'classes': ('collapse',), 'fields': ('disable_pkce',)}),
    )

    def registration_uris(self, request):
        """The URIs of this site that have to be registered for the client at the identity provider."""
        def absolute(name):
            return request.build_absolute_uri(reverse(name))

        return [
            ('Redirect URI (code flow)', absolute('relying_party:callback')),
            ('Redirect URI (implicit flow)', absolute('relying_party:implicit')),
            ('Post logout redirect URI', absolute('relying_party:logged_out')),
            ('Front-channel logout URI', absolute('relying_party:frontchannel_logout')),
            ('Back-channel logout URI', absolute('relying_party:backchannel_logout')),
            ('Initiate login URI', absolute('relying_party:initiate_login')),
        ]

    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        extra_context = {**(extra_context or {}), 'registration_uris': self.registration_uris(request)}
        return super().changeform_view(request, object_id, form_url, extra_context)


@admin.register(ApiClient, site=site)
class ApiClientAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'description': 'The API of this demo (/api/v1/test/) accepts a bearer access token whose iss is the '
                           'identity provider and whose aud is the client_id.',
            'fields': ('identity_provider', 'client_id', 'is_active', 'require_jwt_access_token_type')}),
    )
    list_display = ('identity_provider', 'client_id', 'is_active', 'require_jwt_access_token_type')
    list_filter = ('identity_provider',)


@admin.register(User, site=site)
class UserAdmin(DjangoUserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'identity_provider')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'identity_provider')
    readonly_fields = ('identity_provider', 'sub')
    fieldsets = DjangoUserAdmin.fieldsets + (('OpenID Connect', {'fields': ('identity_provider', 'sub')}),)
