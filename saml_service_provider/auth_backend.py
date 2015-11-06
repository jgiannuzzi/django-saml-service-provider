from django.conf import settings


class GenericSAMLServiceProviderBackend(object):
    user_model = settings.AUTH_USER_MODEL
    nameid_field = 'username'

    def get_nameid_kwargs(self, saml_authentication):
        return {self.nameid_field: saml_authentication.get_nameid()}

    def get_user_from_saml(self, saml_authentication):
        return self.user_model._default_manager.get(
            self.get_nameid_kwargs(saml_authentication))

    def create_user_from_saml(self, saml_authentication):
        user = self.user_model(self.get_nameid_kwargs(saml_authentication))
        user.set_unusable_password()

        return user

    def get_or_create_user_from_saml(self, saml_authentication):
        try:
            user = self.get_user_from_saml(saml_authentication)
        except self.user_model.DoesNotExist:
            user = self.create_user_from_saml(saml_authentication)
            user.save()

        return user

    def authenticate(self, saml_authentication=None):
        if not saml_authentication:  # Using another authentication method
            return None

        if saml_authentication.is_authenticated():
            return self.get_or_create_user_from_saml(saml_authentication)

        return None

    def get_user(self, user_id):
        try:
            return self.user_model._default_manager.get(pk=user_id)
        except self.user_model.DoesNotExist:
            return None


class SAMLServiceProviderBackend(GenericSAMLServiceProviderBackend):
    def create_user_from_saml(self, saml_authentication):
        attributes = saml_authentication.get_attributes()
        user = super(SAMLServiceProviderBackend, self).create_user_from_saml(saml_authentication)
        user.first_name = attributes['First name'][0]
        user.last_name = attributes['Last name'][0]
        return user
