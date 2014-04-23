from oauthlib.oauth1 import WebApplicationServer

from stacksync_oauth.validator import AuthValidator


validator = AuthValidator()
server = WebApplicationServer(validator)