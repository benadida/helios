"""
The Models for Helios.

First the generic stuff, then the extension
"""

#from modelsGAE import *
try:
  from google.appengine.ext import db
  from modelsGAE import *
except:
  from modelsStandalone import *
  
from base import oauth
# example store for one of each thing
class OAuthDataStore(oauth.OAuthDataStore):
  def __init__(self):
    pass
      
  def lookup_consumer(self, key):
    logging.info("looking up consumer %s" % key)
    c = APIClient.selectByKey('consumer_key', key)
    return oauth.OAuthConsumer(c.consumer_key, c.consumer_secret)

  def lookup_token(self, oauth_consumer, token_type, token):
    logging.info("looking up token %s" % token)
    if token_type != 'access':
      raise NotImplementedError

    c = APIClient.selectByKey('consumer_key', oauth_consumer.key)
    return oauth.OAuthToken(c.access_token, c.access_token_secret)

  def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
    """
    Fix this to actually check for nonces
    """
    return None

