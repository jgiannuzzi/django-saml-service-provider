from django.contrib.auth import login, authenticate
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponseBadRequest, HttpResponse, HttpResponseServerError
from django.views.generic import View
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from saml_service_provider.utils import prepare_from_django_request
from django.conf import settings

import logging
logger = logging.getLogger(__name__)


class SAMLMixin(object):
    def get_saml_settings(self):
        raise NotImplementedError("Please define a get_saml_settings method on this view")


class InitiateAuthenticationView(SAMLMixin, View):
    def get(self, *args, **kwargs):
        req = prepare_from_django_request(self.request)
        auth = OneLogin_Saml2_Auth(req, self.get_saml_settings())

        return_url = self.request.GET.get('next', settings.LOGIN_REDIRECT_URL)

        return HttpResponseRedirect(auth.login(return_to=return_url))  # Method that builds and sends the AuthNRequest


class CompleteAuthenticationView(SAMLMixin, View):
    def post(self, request):
        req = prepare_from_django_request(request)
        auth = OneLogin_Saml2_Auth(req, self.get_saml_settings())
        auth.process_response()
        errors = auth.get_errors()
        if not errors:
            if auth.is_authenticated():
                request.session['saml_nameid'] = auth.get_nameid()
                request.session['saml_session_index'] = auth.get_session_index()
                user = authenticate(saml_authentication=auth)
                login(self.request, user)
                if 'RelayState' in req['post_data'] and \
                  OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                    return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))
                else:
                    return HttpResponseRedirect("/")
            else:
                raise PermissionDenied()
        else:
            logger.error(auth.get_last_error_reason(), exc_info=True)
            return HttpResponseBadRequest("Error when processing SAML Response: %s" % (', '.join(errors)))


class InitiateLogoutView(SAMLMixin, View):
    def get(self, *args, **kwargs):
        req = prepare_from_django_request(self.request)
        auth = OneLogin_Saml2_Auth(req, self.get_saml_settings())

        return HttpResponseRedirect(auth.logout(
                name_id=request.session.get('saml_nameid'),
                session_index=request.session.get('saml_session_index')
                ))

class CompleteLogoutView(SAMLMixin, View):
    def post(self, request):
        req = prepare_from_django_request(self.request)
        dscb = lambda: self.request.session.flush()
        auth = OneLogin_Saml2_Auth(req, self.get_saml_settings())

        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if not errors:
            if url:
                return HttpResponseRedirect(url)
            else:
                return HttpResponseRedirect(settings.LOGOUT_REDIRECT_URL)
        else:
            logger.error(auth.get_last_error_reason(), exc_info=True)
            return HttpResponseBadRequest('Error when processing SAML Logout Request: {}'.format(', '.join(errors)))


class MetadataView(SAMLMixin, View):
    def get(self, request, *args, **kwargs):
        req = prepare_from_django_request(request)
        auth = OneLogin_Saml2_Auth(req, self.get_saml_settings())
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        if len(errors) == 0:
            return HttpResponse(content=metadata, content_type='text/xml')
        else:
            return HttpResponseServerError(content=', '.join(errors))
