"""
A session manager.

This doesn't do much with GAE yet. Most of the code here is currently comatose.

2008-01-16
ben@adida.net
"""

import cherrypy
import logging

try:
  from google.appengine.api import users
except:
  pass

from base import oauth

def get_session():
    if not hasattr(cherrypy.serving,'base_session') or cherrypy.serving.base_session == None:
        cherrypy.serving.base_session = Session()

    return cherrypy.serving.base_session

def get_status():
    return get_session().get_status()

def set_status(status):
    get_session().set_status(status)

def get_api_client():
  """
  Determine if this is an API client making the call
  """
  # verify the OAuth request
  request = cherrypy.request

  oauth_request = oauth.OAuthRequest.from_request(request.method, request.path_info, headers= request.headers,
                                                  parameters=request.params, query_string=None)
                                                  
  if not oauth_request:
    return None
    
  try:
    consumer, token, params = Session.OAUTH_SERVER.verify_request(oauth_request)
    return consumer
  except oauth.OAuthError:
    return None
  

def login_protect(func, redirect_to = None):
    """
    A decorator that enables checks that the request is authenticated
    """
    def ensure_auth(self, *args, **kwargs):
      if not get_session().get_user() and not get_api_client():
        raise cherrypy.HTTPRedirect(redirect_to or users.create_login_url("/"))
        
      return func(self, *args, **kwargs)
    
    return ensure_auth

def admin_protect(func, redirect_to = None):
  """
  A decorator that enables checks that the request is authenticated
  """
  def ensure_admin(self, *args, **kwargs):
    if not get_session().is_admin():
      raise cherrypy.HTTPRedirect(redirect_to or users.create_login_url("/"))
      
    return func(self, *args, **kwargs)
  
  return ensure_admin

def logout():
    get_session().logout()

class Session:
  ## OAUTH

  OAUTH_SERVER = None

  @classmethod
  def setup_oauth(cls, oauth_datastore):
    Session.OAUTH_SERVER = oauth.OAuthServer(oauth_datastore)
    Session.OAUTH_SERVER.add_signature_method(oauth.OAuthSignatureMethod_HMAC_SHA1())

  def __init__(self, cherrypy_session=None):
    self._user = users.get_current_user()
    if self._user:
      self._user.email_address = self._user.email()
    self._admin_p = users.is_current_user_admin()
    #if self.has_key('user_id'):
    #    self._user = do.User.selectById(self["user_id"])

  def __getitem__(self, key):
    if self._cp_session.has_key(key):
      return self._cp_session[key]
    else:
      return None

  def __setitem__(self, key, value):
    self._cp_session[key] = value

  def __delitem__(self, key):
    del self._cp_session[key]

  def has_key(self, key):
    return self._cp_session.has_key(key)

  def logout(self):
    self._user = None
    #del self['user_id']
        
  def get_user(self):
    return self._user
        
  def set_user(self, user):
    self._user = user

  def set_status(self, status):
    pass
    #self['__status'] = status

  def get_status(self):
    return ""
        
  def is_admin(self):
    return self._admin_p

