import os
import hashlib


def get_new_token():
    """Returns a randomly generated 32-character string to be used as request or access token"""
    return hashlib.md5(os.urandom(32)).hexdigest()

def get_new_verifier():
    """Returns a randomly generated 10-character string to be used as a verifier"""
    return hashlib.md5(os.urandom(32)).hexdigest()[:10]