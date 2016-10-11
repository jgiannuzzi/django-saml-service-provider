from django.conf import settings
from django.contrib.auth import get_user_model


class SAMLUserProxy(object):
    user_model = get_user_model()
    nameid_field = user_model.USERNAME_FIELD

    def __init__(self, saml_authentication):
        self.saml_authentication = saml_authentication
        self.attribute_mappings = getattr(settings,
                                          'SAML_USER_ATTRIBUTE_MAPPINGS', {})

    @property
    def attributes(self):
        return self.saml_authentication.get_attributes()

    @property
    def nameid(self):
        return self.saml_authentication.get_nameid()

    def get_user_kwargs(self):
        return {self.nameid_field: self.nameid}

    def get_user(self):
        return self.user_model._default_manager.get(**self.get_user_kwargs())

    def create_user(self):
        user = self.user_model(**self.get_user_kwargs())
        user.set_unusable_password()

        for user_attr, saml_attr in self.attribute_mappings.items():
            setattr(user, user_attr, self.attributes[saml_attr][0])

        return user

    def get_or_create_user(self):
        try:
            user = self.get_user()
        except self.user_model.DoesNotExist:
            user = self.create_user()
            user.save()

        return user


class SAMLServiceProviderBackend(object):
    user_proxy_class = SAMLUserProxy

    def authenticate(self, saml_authentication=None):
        if not saml_authentication:  # Using another authentication method
            return None

        if saml_authentication.is_authenticated():
            return self.user_proxy_class(
                saml_authentication).get_or_create_user()

        return None

    def get_user(self, user_id):
        user_model = get_user_model()
        try:
            return user_model._default_manager.get(pk=user_id)
        except user_model.DoesNotExist:
            return None
