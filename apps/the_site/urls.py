from django.urls import include, path

from relying_party.admin import site as admin_site

urlpatterns = [
    path('', include('relying_party.urls')),
    path('admin/', admin_site.urls),
]
