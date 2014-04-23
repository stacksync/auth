# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import psycopg2
from psycopg2.extras import DictCursor
from oauthlib.common import safe_string_equals, to_unicode
from oauthlib.oauth1.rfc5849 import Server, SIGNATURE_PLAINTEXT, SIGNATURE_HMAC

from stacksync_oauth import utils


class AuthServer(Server):
    
    def __init__(self, host='localhost', port='5432', 
                 dbname='oauth', user='postgres', password='postgres'):
        self.conn_string = "host=%s port=%s dbname=%s user=%s password=%s" % (host, port, dbname, user, password)
    
    @property
    def allowed_signature_methods(self):
        return (SIGNATURE_PLAINTEXT, SIGNATURE_HMAC)
    
    @property
    def client_key_length(self):
        return 32, 64

    @property
    def request_token_length(self):
        return 32, 64

    @property
    def access_token_length(self):
        return 32, 64

    @property
    def enforce_ssl(self):
        return False

    @property
    def dummy_request_token(self):
        return '00000000000000000000000000000000'
    
    @property
    def timestamp_lifetime(self):
        return 600

    def get_client_secret(self, client_key):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        cur.execute("SELECT osr_consumer_secret FROM oauth_server_registry WHERE osr_consumer_key = %s;", (client_key, ))
        client_secret = cur.fetchone()
        if client_secret:
            return to_unicode(client_secret[0], 'utf-8')
        else:
            return None

    def get_access_token_secret(self, client_key, access_token):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            SELECT ost.ost_token_secret
            FROM oauth_server_token ost
            INNER JOIN oauth_server_registry osr ON ost.ost_osr_id_ref = osr.osr_id
            WHERE ost.ost_token = %s
            AND ost.ost_token_type = 'access'
            AND osr.osr_consumer_key = %s;
            """
        cur.execute(query, (access_token, client_key ))
        token_secret = cur.fetchone()
        if token_secret:
            return to_unicode(token_secret[0], 'utf-8')
        else:
            return None

    def get_request_token_secret(self, client_key, request_token):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            SELECT ost.ost_token_secret
            FROM oauth_server_token ost
            INNER JOIN oauth_server_registry osr ON ost.ost_osr_id_ref = osr.osr_id
            WHERE ost.ost_token = %s
            AND ost.ost_token_type = 'request'
            AND osr.osr_consumer_key = %s;
            """
        cur.execute(query, (request_token, client_key ))
        token_secret = cur.fetchone()
        if token_secret:
            return to_unicode(token_secret[0], 'utf-8')
        else:
            # returns the dummy token at the end to 
            # keep the same running time as for valid requests 
            return request_token if request_token == self.dummy_request_token else None

    def get_rsa_key(self, client_key):
        return "0987654321"

    def validate_client_key(self, client_key):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        cur.execute("SELECT osr_consumer_key FROM oauth_server_registry WHERE osr_consumer_key = %s AND osr_enabled = '1';", (client_key, ))
        results = cur.fetchone()
        if results:
            return True
        else:
            return False

    def validate_access_token(self, client_key, access_token):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            SELECT ost.ost_token
            FROM oauth_server_token ost
            INNER JOIN oauth_server_registry osr ON ost.ost_osr_id_ref = osr.osr_id
            WHERE ost.ost_token = %s
            AND ost.ost_token_type = 'access'
            AND osr.osr_consumer_key = %s;
            """
        cur.execute(query, (access_token, client_key ))
        results = cur.fetchone()
        if results:
            return True
        else:
            return False

    def validate_request_token(self, client_key, request_token):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            SELECT ost.ost_token
            FROM oauth_server_token ost
            INNER JOIN oauth_server_registry osr ON ost.ost_osr_id_ref = osr.osr_id
            WHERE ost.ost_token = %s
            AND ost.ost_authorized = True 
            AND ost.ost_token_type = 'request'
            AND osr.osr_consumer_key = %s;
            """
        cur.execute(query, (request_token, client_key ))
        results = cur.fetchone()
        if results:
            return True
        else:
            return False

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
        token):
        
        if not token:
            token = ''
        
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            SELECT MAX(osn_timestamp), MAX(osn_timestamp) > %s + %s
                FROM oauth_server_nonce
                WHERE osn_consumer_key = %s
                AND osn_token = %s
            """
            
        values = (timestamp, self.timestamp_lifetime, client_key, token)
            
        cur.execute(query, values)
        results = cur.fetchone()
        
        # check if timestamp is in sequence
        if results and results[1]:
            #raise ValueError("Timestamp is out of sequence.")
            return False
        
        try:
            self._insert_timestamp_and_nonce(client_key, timestamp, nonce, token)
        except Exception as inst:
            print inst
            #raise ValueError("Duplicate timestamp/nonce combination.")
            return False
        
        self._clean_log_old_timestamp(client_key, timestamp, token)
        
        return True
    
    def _insert_timestamp_and_nonce(self, client_key, timestamp, nonce,
        token):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            INSERT INTO oauth_server_nonce (
                osn_consumer_key,
                osn_token, 
                osn_timestamp,
                osn_nonce
            )
            VALUES (%s, %s, %s, %s);
            """
        cur.execute(query, (client_key, token, timestamp, nonce))
        conn.commit()


    def _clean_log_old_timestamp(self, client_key, timestamp, token):
       
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            DELETE FROM oauth_server_nonce
            WHERE osn_consumer_key    = %s
            AND osn_token            = %s
            AND osn_timestamp     < %s - %s
            """
        cur.execute(query, (client_key, token, timestamp, self.timestamp_lifetime))
        conn.commit()
        
    def validate_requested_realm(self, client_key, realm):
        return True

    def validate_realm(self, client_key, realm, uri,
            request_token=None, access_token=None, required_realm=None):
        return True

    def validate_verifier(self, client_key, request_token, verifier):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
            SELECT ost.ost_token
            FROM oauth_server_token ost
            INNER JOIN oauth_server_registry osr ON ost.ost_osr_id_ref = osr.osr_id
            WHERE ost.ost_token = %s
            AND osr.osr_consumer_key = %s 
            AND ost.ost_verifier = %s;
            """
        cur.execute(query, (request_token, client_key, verifier ))
        results = cur.fetchone()
        if results:
            return True
        else:
            return False
        
    def validate_redirect_uri(self, client_key, redirect_uri):
        # checks if the callback has been established via other means,
        # The string "oob" (case sensitive) indicates an out-of-band configuration.
        if safe_string_equals(redirect_uri, "oob"):
            return True
        
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        query = """
                SELECT osr_callback_uri 
                FROM oauth_server_registry 
                WHERE osr_consumer_key = %s
                """
        cur.execute(query, (client_key, ))
        callback = cur.fetchone()
        if callback:
            return safe_string_equals(callback[0], redirect_uri)
        else:
            return False

    def create_request_token(self, request):
        token = utils.get_new_token()
        secret = utils.get_new_token()
        
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        cur.execute("SELECT osr_id FROM oauth_server_registry WHERE osr_consumer_key = %s AND osr_enabled = '1';", (request.client_key, ))
        result = cur.fetchone()
        
        if not result:
            raise ValueError("Invalid customer key.")
        
        osr_id = result[0]
        
        query = """
            INSERT INTO oauth_server_token (
                ost_osr_id_ref,
                ost_usa_id_ref,
                ost_token,
                ost_token_secret,
                ost_token_type,
                ost_callback_url
            )
            VALUES (%s, '1', %s, %s, 'request', %s);
            """
        cur.execute(query, (osr_id, token, secret, request.callback_uri))
        conn.commit()
        
        return token, secret
        
    def verify_authorize(self, request_token):
        conn = psycopg2.connect(self.conn_string, cursor_factory=DictCursor)
        cur = conn.cursor()
        query = """
            SELECT    ost_token            as token,
                        ost_token_secret    as token_secret,
                        osr_consumer_key    as consumer_key,
                        osr_consumer_secret    as consumer_secret,
                        ost_token_type        as token_type,
                         ost_callback_url    as callback_url,
                         osr_application_title as application_title,
                         osr_application_descr as application_descr,
                         osr_application_uri   as application_uri
                FROM oauth_server_token
                        JOIN oauth_server_registry
                        ON ost_osr_id_ref = osr_id
                WHERE ost_token_type = 'request'
                  AND ost_token      = %s
                  AND ost_authorized = False
            """
            
        # TODO: check if token has expired?
         
        cur.execute(query, (request_token, ))
        result = cur.fetchone()
        
        if not result:
            raise ValueError("Invalid request token")
        
        info = {}
        info['token'] = result['token']
        info['callback_url'] = result['callback_url']
        info['application_title'] = result['application_title']
        info['application_descr'] = result['application_descr']
        info['application_uri'] = result['application_uri']
        
        return info
    
    def authorize_consumer_request_token(self, request_token, user_id):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        
        verifier = utils.get_new_verifier()
        
        query = """
            UPDATE oauth_server_token
                    SET ost_authorized    = '1',
                        ost_usa_id_ref    = %s,
                        ost_timestamp     = NOW(),
                        ost_verifier      = %s
                    WHERE ost_token      = %s
                      AND ost_token_type = 'request'
                """
        cur.execute(query, (user_id, verifier, request_token, ))
        conn.commit()
        return verifier
    
    def delete_consumer_request_token(self, request_token):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        
        query = """
                DELETE FROM oauth_server_token
                WHERE ost_token      = %s
                AND ost_token_type = 'request'
                """
        cur.execute(query, (request_token, ))
        conn.commit()
    
    def exchange_request_token_for_access_token(self, request_token, verifier):
        conn = psycopg2.connect(self.conn_string)
        cur = conn.cursor()
        
        access_token = utils.get_new_token()
        access_token_secret = utils.get_new_token()
        
        query = """
            UPDATE oauth_server_token
            SET ost_token            = %s,
              ost_token_secret    = %s,
              ost_token_type        = 'access',
              ost_timestamp        = NOW()
            WHERE ost_token      = %s
            AND ost_token_type = 'request'
            AND ost_authorized = '1'
            AND ost_verifier = %s
            """
        cur.execute(query, (access_token, access_token_secret, request_token, verifier ))
        rows_affected = cur.rowcount
        conn.commit()       
        
        if not rows_affected:
            raise ValueError('Can\'t exchange request token for access token. No such token or not authorized')
        
        return access_token, access_token_secret
    
    def verify_permission_to_workspace(self, owner_id, workspace, access_token):
        # TODO: check if the requester user (access_token) can access the desired workspace (owner_id & workspace)
        return True
        
        
        