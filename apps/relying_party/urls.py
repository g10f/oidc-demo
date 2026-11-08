from django.urls import path

from . import views

app_name = 'relying_party'

urlpatterns = [
    path('', views.home, name='home'),
    path('oidc/login/', views.login_page, name='login'),
    path('oidc/login/<int:client_id>/', views.start_login, name='start_login'),
    path('oidc/callback/', views.callback, name='callback'),
    # The callback of the versions before 3.0, still registered at the identity providers.
    path('oauth2/login/', views.callback, name='callback_legacy'),
    path('oidc/logout/', views.logout, name='logout'),
    path('oidc/logged-out/', views.logged_out, name='logged_out'),
    path('oidc/tokens/', views.tokens, name='tokens'),
    path('oidc/tokens/refresh/', views.refresh_tokens, name='refresh_tokens'),
    path('oidc/userinfo/', views.userinfo, name='userinfo'),
    path('oidc/userinfo/picture/', views.picture, name='picture'),
    path('oidc/profile/', views.profile, name='profile'),
    path('oidc/device/', views.device, name='device'),
    path('oidc/device/<int:client_id>/', views.device_start, name='device_start'),
    path('oidc/device/poll/', views.device_poll, name='device_poll'),
    path('oidc/device/cancel/', views.device_cancel, name='device_cancel'),
    path('oidc/implicit/', views.implicit, name='implicit'),
    path('oidc/initiate/', views.initiate_login, name='initiate_login'),
    path('oidc/frontchannel-logout/', views.frontchannel_logout, name='frontchannel_logout'),
    path('oidc/backchannel-logout/', views.backchannel_logout, name='backchannel_logout'),
    path('oidc/session-iframe/', views.session_iframe, name='session_iframe'),
    path('api/v1/test/', views.api_test, name='api_test'),
]
