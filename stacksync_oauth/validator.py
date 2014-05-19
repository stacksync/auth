import logging
import datetime
from oauthlib.oauth1 import RequestValidator, SIGNATURE_PLAINTEXT, SIGNATURE_HMAC
from sqlalchemy.orm.exc import NoResultFound

from stacksync_oauth.models import Consumer, RequestToken, Nonce, ResourceOwner
from stacksync_oauth.models import AccessToken

log = logging.getLogger('stacksync_oauth')


class AuthValidator(RequestValidator):
    def __init__(self, dbsession):
        self.dbsession = dbsession

    @property
    def enforce_ssl(self):
        return False

    @property
    def client_key_length(self):
        return 30, 64

    @property
    def request_token_length(self):
        return 30, 64

    @property
    def access_token_length(self):
        return 30, 64

    @property
    def nonce_length(self):
        return 16, 64

    @property
    def verifier_length(self):
        return 16, 64

    @property
    def realms(self):
        return ['stacksync']

    @property
    def allowed_signature_methods(self):
        return (SIGNATURE_PLAINTEXT, SIGNATURE_HMAC)

    @property
    def dummy_request_token(self):
        return '00000000000000000000000000000000'

    @property
    def dummy_access_token(self):
        return '00000000000000000000000000000000'

    @property
    def dummy_client(self):
        return '00000000000000000000000000000000'

    def validate_client_key(self, client_key, request):
        """Validates that supplied client key."""
        log.debug('Validate client key for client %r', client_key)
        try:
            self.dbsession.query(Consumer).filter_by(consumer_key=client_key).one()
            return True
        except NoResultFound:
            return False

    def validate_request_token(self, client_key, token, request):
        """Validates request token is available for client."""
        log.debug('Validate request token %r for client %r',
                  token, client_key)
        try:
            request_token, consumer = self.dbsession.query(RequestToken, Consumer).join(Consumer,
                                                                                        RequestToken.consumer == Consumer.id).filter(
                RequestToken.request_token == token, Consumer.consumer_key == client_key).one()
            if consumer.consumer_key == client_key:
                request.request_token = request_token
                return True
            return False
        except NoResultFound:
            return False

    def validate_access_token(self, client_key, token, request):
        """Validates access token is available for client."""
        log.debug('Validate access token %r for client %r',
                  token, client_key)
        try:
            access_token, consumer, user = self.dbsession.query(AccessToken, Consumer, ResourceOwner)\
                .join(Consumer, AccessToken.consumer == Consumer.id)\
                .join(ResourceOwner, AccessToken.user == ResourceOwner.id)\
                .filter(AccessToken.access_token == token, Consumer.consumer_key == client_key)\
                .one()
            if consumer.consumer_key == client_key:
                request.access_token = access_token
                request.user = user
                return True
            return False
        except NoResultFound:
            return False

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
                                     request, request_token=None, access_token=None):
        """Validate the timestamp and nonce is used or not."""
        log.debug('Validate timestamp and nonce for client %r', client_key)
        token = request_token or access_token
        try:
            self.dbsession.query(Nonce).filter_by(consumer_key=client_key, timestamp=timestamp, nonce=nonce,
                                                  token=token).one()
            return False
        except NoResultFound:
            n = Nonce()
            n.nonce = nonce
            n.timestamp = timestamp
            n.consumer_key = client_key
            n.token = token
            self.dbsession.add(n)
            self.dbsession.commit()
            return True

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        """Validate if the redirect_uri is allowed by the client."""
        log.debug('Validate redirect_uri %r for %r', redirect_uri, client_key)

        if not request.client:
            request.client = self.dbsession.query(Consumer).filter_by(consumer_key=client_key).first()
        if not request.client:
            return False
        if not request.client.redirect_uri and redirect_uri is None:
            return True
        request.redirect_uri = redirect_uri
        return redirect_uri == request.client.redirect_uri or redirect_uri == 'oob'

    def validate_requested_realms(self, client_key, realms, request):
        """Validates that the client may request access to the realm"""
        log.debug('Validate requested realms %r for client %r', realms, client_key)
        #TODO: implement
        return True

    def validate_realms(self, client_key, token, request, uri=None,
                        realms=None):
        """Check if the token has permission on those realms."""
        log.debug('Validate realms %r for client %r', realms, client_key)
        #TODO: implement
        return True

    def validate_verifier(self, client_key, token, verifier, request):
        """Validate if verifier exists."""
        log.debug('Validate verifier %r for client %r', verifier, client_key)

        if request.request_token:
            return request.request_token.verifier == verifier

        try:
            _, _ = self.dbsession.query(RequestToken, Consumer).join(Consumer,
                                                                     RequestToken.consumer == Consumer.id).filter(
                RequestToken.request_token == token, RequestToken.verifier == verifier,
                Consumer.consumer_key == client_key).one()
            return True
        except NoResultFound:
            return False

    def invalidate_request_token(self, client_key, request_token, request):
        """Invalidates a used request token."""
        log.debug('Invalidate token for client %r, request token %r', client_key, request_token)
        try:
            consumer = self.dbsession.query(Consumer).filter_by(consumer_key=request.client_key).one()
            self.dbsession.query(RequestToken).filter_by(consumer=consumer.id, request_token=request_token).delete()
            self.dbsession.commit()
        except Exception as inst:
            log.error('Could not invalidate request token %r for client %r', request_token, client_key)
            self.dbsession.rollback()

    def get_client_secret(self, client_key, request):
        """Get client secret.

        The client object must has ``client_secret`` attribute.
        """
        log.debug('Get client secret of %r', client_key)
        try:
            consumer = self.dbsession.query(Consumer).filter_by(consumer_key=client_key).one()
            return consumer.consumer_secret
        except NoResultFound:
            return None

    def get_request_token_secret(self, client_key, token, request):
        """Get request token secret.

        The request token object should a ``secret`` attribute.
        """
        log.debug('Get request token secret of %r for client %r',
                  token, client_key)
        try:
            request_token = self.dbsession.query(RequestToken).filter_by(request_token=token).one()
            return request_token.request_token_secret
        except NoResultFound:
            return None

    def get_access_token_secret(self, client_key, token, request):
        """Get access token secret.

        The access token object should a ``secret`` attribute.
        """
        log.debug('Get access token secret of %r for client %r',
                  token, client_key)
        try:
            access_token = self.dbsession.query(AccessToken).filter_by(access_token=token).one()
            return access_token.access_token_secret
        except NoResultFound:
            return None

    def get_default_realms(self, client_key, request):
        """Default realms of the client."""
        log.debug('Get default realms for client %r', client_key)
        return ['stacksync']

    def get_realms(self, token, request):
        """Realms for this request token."""
        log.debug('Get realms of token %r', token)
        return ['stacksync']

    def save_request_token(self, token, request):
        """Save request token to database. """
        log.debug('Save request token %r', token)
        try:
            consumer = self.dbsession.query(Consumer).filter_by(consumer_key=request.client_key).one()
            request_token = RequestToken()
            request_token.consumer = consumer.id
            request_token.realm = "stacksync"
            request_token.redirect_uri = request.redirect_uri
            request_token.request_token = token['oauth_token']
            request_token.request_token_secret = token['oauth_token_secret']
            self.dbsession.add(request_token)
            self.dbsession.commit()
            return True
        except NoResultFound:
            return None
        except Exception as inst:
            log.error('Error saving request token: %s' % inst)
            self.dbsession.rollback()
            return None

    def save_verifier(self, token, verifier, request):
        """Save verifier to database. """
        log.debug('Save verifier %r', verifier)
        try:
            r = self.dbsession.query(RequestToken).filter_by(request_token=token).one()
            r.verifier = verifier
            r.user = request.resource_owner_key
            r.modified_at = datetime.datetime.now()
            self.dbsession.commit()
            return verifier
        except NoResultFound:
            return None
        except Exception as inst:
            log.error('Error saving access token: %s' % inst)
            self.dbsession.rollback()

    def save_access_token(self, token, request):
        """Save access token to database. """
        log.debug('Save access token %r', token)
        try:
            consumer = self.dbsession.query(Consumer).filter_by(consumer_key=request.client_key).one()
            access_token = AccessToken()
            access_token.user = request.request_token.user
            access_token.consumer = consumer.id
            access_token.realm = "stacksync"
            access_token.redirect_uri = request.redirect_uri
            access_token.access_token = token['oauth_token']
            access_token.access_token_secret = token['oauth_token_secret']
            self.dbsession.add(access_token)
            self.dbsession.commit()
            return True
        except NoResultFound:
            return None
        except Exception as inst:
            log.error('Error saving access token: %s' % inst)
            self.dbsession.rollback()
            return None

    def verify_authorize(self, request_token):
        """Verifies that the given request token is valid and returns the RequestToken object. """
        log.debug('Verify authorize for token %r', request_token)
        try:
            r = self.dbsession.query(RequestToken).filter_by(request_token=request_token).one()
            if not r.consumer:
                return None
            if r.verifier:
                # This token has been already authorized
                return None
            c = self.dbsession.query(Consumer).filter_by(id=r.consumer).one()
            return r, c
        except NoResultFound:
            return None

    def verify_user_email(self, email):
        """Validates and returns the user with the given email."""
        log.debug('Validate user email %r', email)
        try:
            return self.dbsession.query(ResourceOwner).filter_by(email=email).one()
        except NoResultFound:
            return None
