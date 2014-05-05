import logging.config
import urllib
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session

from twisted.web import server, resource
from twisted.web._flatten import flattenString
from twisted.web.http_headers import Headers
from twisted.web.server import Session
from twisted.web.template import Element, renderer, XMLFile
from twisted.internet import reactor
from twisted.python.components import registerAdapter
from zope.interface import Interface, Attribute, implements
from sqlalchemy.orm.session import sessionmaker
from stacksync_oauth.models import Base
from stacksync_oauth.provider import AuthProvider
from stacksync_oauth.validator import AuthValidator


class ISessionInfo(Interface):
    request_token = Attribute("")
    callback_url = Attribute("")


class SessionInfo(object):
    implements(ISessionInfo)

    def __init__(self, session):
        self.request_token = None
        self.consumer = None


registerAdapter(SessionInfo, Session, ISessionInfo)


class AuthorizeElement(Element):
    loader = XMLFile('authorize.xml')

    def __init__(self, consumer):
        self.consumer = consumer

    @renderer
    def user_name(self, request, tag):
        return tag(self.consumer.consumer_key)

    @renderer
    def application_title(self, request, tag):
        return tag(self.consumer.application_title)

    @renderer
    def application_descr(self, request, tag):
        return tag(self.consumer.application_description)

        # @renderer
        # def session(self, request, tag):
        #    tag.fillSlots(session_uid=self.info['session_uid'])
        #    return tag


class Simple(resource.Resource):
    isLeaf = False

    def getChild(self, name, request):
        if name == '':
            return self
        return resource.Resource.getChild(self, name, request)

    def render_GET(self, request):
        user, token, consumer = provider.verify_authorize_submission('pNaNIcpyQtNOpEqL8GOBS9Dt6Cw4kv', 'a@a.a')
        result2 = provider.authorize_request_token(token.request_token, user.id)
        return result, result2

        #return "Prepath=%r, Args=%r" % (request.prepath, request.args,)
        # return "Hello, world! I am located at %r." % (request.prepath,)


class RequestTokenResource(resource.Resource):
    isLeaf = True

    def __init__(self, p):
        self.provider = p

    def render(self, request):
        headers = {}
        for k, v in request.received_headers._headers.getAllRawHeaders():
            headers[k] = v[-1]

        body = request.content.getvalue()
        url = 'http://localhost:8080%s' % (request.uri,)

        h, b, s = provider.create_request_token_response(url, http_method=request.method, body=body,
                                                         headers=headers)
        for key, elem in h.items():
            request.responseHeaders.addRawHeader(key.encode('utf-8'), elem.encode('utf-8'))
        request.setResponseCode(s)
        if b:
            request.write(b.encode('utf-8'))
        request.finish()

        return server.NOT_DONE_YET


class AuthorizeResource(resource.Resource):
    isLeaf = True
    sessions = set()

    def __init__(self, p):
        self.provider = p

    def render_GET(self, request):
        try:
            token_list = request.args['oauth_token']
        except KeyError:
            request.setResponseCode(400)
            request.write("Missing oauth token")
            request.finish()
            return server.NOT_DONE_YET

        token = token_list[-1]
        result = provider.verify_authorize_request(token)

        if not result:
            request.setResponseCode(400)
            request.write("Invalid oauth token")
            request.finish()
            return server.NOT_DONE_YET

        request_token, consumer = result

        session = request.getSession()
        if session.uid not in self.sessions:
            self.sessions.add(session.uid)

        session_info = ISessionInfo(session)
        session_info.request_token = request_token
        session_info.consumer = consumer
        template = AuthorizeElement(consumer)

        flattenString(request, template).addCallback(request.write)
        request.finish()
        return server.NOT_DONE_YET

    def render_POST(self, request):
        # get the user from a session
        user_id = 1

        session = request.getSession()

        if session.uid not in self.sessions:
            return "Invalid session"

        session_info = ISessionInfo(session)

        if not session_info or not session_info.request_token:
            request.write("Session expired")
            request.finish()
            return server.NOT_DONE_YET

        action = request.args['action']
        if not action:
            request.setResponseCode(400)
            request.finish()
            return server.NOT_DONE_YET

        if 'Allow' not in action:
            #TODO: delete request token (session_info.request_token)
            request.write("Authorization rejected")
            request.finish()
            return server.NOT_DONE_YET

        verifier = provider.authorize_request_token(session_info.request_token.request_token, user_id)

        if not verifier:
            request.write("Could not authorize request token")
            request.finish()
            return server.NOT_DONE_YET

        if session_info.request_token.redirect_uri == 'oob':
            request.write("Authorization granted.<br />\n")
            request.write("Request token: %s<br />\n" % (session_info.request_token.request_token.encode('utf8'), ))
            request.write("Verifier: %s\n" % (verifier.encode('utf8'), ))
        else:
            params = {}
            params['verifier'] = verifier
            params['token'] = session_info.request_token.request_token
            encoded_params = urllib.urlencode(params)
            redirect_url = session_info.request_token.redirect_uri + "?" + encoded_params
            request.redirect(redirect_url.encode('utf8'))

        request.finish()
        return server.NOT_DONE_YET


class AccessTokenResource(resource.Resource):
    isLeaf = True

    def __init__(self, provider):
        self.provider = provider

    def render(self, request):
        headers = {}
        for k, v in request.received_headers._headers.getAllRawHeaders():
            headers[k] = v[-1]

        body = request.content.getvalue()
        url = 'http://localhost:8080%s' % (request.uri,)

        credentials = {'user_id': '1'}

        h, b, s = provider.create_access_token_response(url, http_method=request.method, body=body, headers=headers,
                                                        credentials=credentials)

        for key, elem in h.items():
            request.responseHeaders.addRawHeader(key.encode('utf-8'), elem.encode('utf-8'))
        request.setResponseCode(s)
        if b:
            request.write(b.encode('utf-8'))
        request.finish()

        return server.NOT_DONE_YET


class ProtectedResource(resource.Resource):
    isLeaf = True

    def __init__(self, provider):
        self.provider = provider

    def render(self, request):
        """
        auth_server = AuthServer()
        method = request.method
        uri = request.uri
        headers = request.received_headers.copy()
        body = request.content.getvalue()
        requested_uri = 'http://%s%s' % (headers['host'], uri)

        try:
            result, params = auth_server.verify_request(requested_uri,
                                                        http_method=method,
                                                        body=body,
                                                        headers=headers,
                                                        require_resource_owner=True,
                                                        require_verifier=False,
                                                        require_realm=False,
                                                        require_callback=False)

            if not result:
                request.setResponseCode(401)
                request.write("Validation failed")
                request.finish()
                return server.NOT_DONE_YET

        except ValueError as inst:
            request.setResponseCode(400)
            request.write(str(inst))
            request.finish()
            return server.NOT_DONE_YET

        """
        request.write("OK")
        request.finish()
        return server.NOT_DONE_YET


Headers._caseMappings['content-type'] = 'Content-Type'

dbsession = scoped_session(sessionmaker())
#engine = create_engine("sqlite:///foo.db", echo=False)
engine = create_engine("postgresql://stacksync_user:stacksync@localhost/stacksync")
dbsession.configure(bind=engine, autoflush=False, expire_on_commit=False)

#Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)

validator = AuthValidator(dbsession)
provider = AuthProvider(validator)

logging.config.fileConfig('log.conf')
log = logging.getLogger('stacksync_oauth')
log.info('Initializing authentication webserver...')

root = Simple()
oauth = Simple()
root.putChild('oauth', oauth)
oauth.putChild('request_token', RequestTokenResource(provider))
oauth.putChild('authorize', AuthorizeResource(provider))
oauth.putChild('access_token', AccessTokenResource(provider))
oauth.putChild('resource', ProtectedResource(provider))

site = server.Site(root)
reactor.listenTCP(8080, site)

log.info("Authentication webserver up and running")

reactor.run()


