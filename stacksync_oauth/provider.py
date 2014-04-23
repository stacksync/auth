from __future__ import absolute_import, unicode_literals
from oauthlib.oauth1 import RequestTokenEndpoint, AuthorizationEndpoint, ResourceEndpoint, AccessTokenEndpoint
from oauthlib.common import Request


class AuthProvider(RequestTokenEndpoint, AuthorizationEndpoint,
                   AccessTokenEndpoint, ResourceEndpoint):

    def __init__(self, request_validator):
        RequestTokenEndpoint.__init__(self, request_validator)
        AuthorizationEndpoint.__init__(self, request_validator)
        AccessTokenEndpoint.__init__(self, request_validator)
        ResourceEndpoint.__init__(self, request_validator)

    def verify_authorize_request(self, request_token):
        return self.request_validator.verify_authorize(request_token)

    def authorize_request_token(self, request_token, user):
        verifier = self.token_generator()
        request = Request('')
        request.resource_owner_key = user
        return self.request_validator.save_verifier(request_token, verifier, request)