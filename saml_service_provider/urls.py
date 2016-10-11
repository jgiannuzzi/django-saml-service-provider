from django.conf.urls import patterns, include, url
from django.views.decorators.csrf import csrf_exempt
from saml_service_provider.views import MetadataView, CompleteAuthenticationView, InitiateAuthenticationView, CompleteLogoutView, InitiateLogoutView

app_name = 'saml_service_provider'

urlpatterns = patterns('',
    url(r'^initiate-login/$', InitiateAuthenticationView.as_view(), name="login_initiate"),
    url(r'^complete-login/$', csrf_exempt(CompleteAuthenticationView.as_view()), name="login_complete"),
    url(r'^initiate-logout/$', InitiateLogoutView.as_view(), name="logout_initiate"),
    url(r'^complete-logout/$', csrf_exempt(CompleteLogoutView.as_view()), name="logout_complete"),
    url(r'^metadata/$', MetadataView.as_view(), name="metadata"),
)
