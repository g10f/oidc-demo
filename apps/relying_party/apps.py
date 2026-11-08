from django.apps import AppConfig


class RelyingPartyConfig(AppConfig):
    name = 'relying_party'
    verbose_name = 'OpenID Connect relying party'
    default_auto_field = 'django.db.models.BigAutoField'
