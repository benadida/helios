"""
A session manager.

This doesn't do much with GAE yet. Most of the code here is currently comatose.

2008-01-16
ben@adida.net
"""

import cherrypy

try:
  from google.appengine.api import users
except:
  pass

import models as do

def get_session():
    if not hasattr(cherrypy.serving,'base_session') or cherrypy.serving.base_session == None:
        cherrypy.serving.base_session = Session()

    return cherrypy.serving.base_session

def get_status():
    return get_session().get_status()

def set_status(status):
    get_session().set_status(status)
    
def login_protect(func, redirect_to = None):
    """
    A decorator that enables cherrypy
    but also that enables certain global property checking
    """
    def ensure_user_logged_in(self, *args, **kwargs):
        if not get_session().get_user():
            raise cherrypy.HTTPRedirect(redirect_to or users.create_login_url("/"))
        
        return func(self, *args, **kwargs)
    
    return ensure_user_logged_in


def login_protect_class(cls, redirect_to = None):
    def ensure_user_logged_in(self):
        if not get_session().get_user():
            raise cherrypy.HTTPRedirect(redirect_to or users.create_login_url("/"))
        
    cls.before_filter = ensure_user_logged_in

def logout():
    get_session().logout()

class Session:
    def __init__(self, cherrypy_session=None):
        self._user = users.get_current_user()
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

    def login(self, email, password):
        user = do.User.select_by_email(email)
        if not user:
            raise Exception('no such user')

        if not user.verified_p:
            self.set_status('Your account has not been verified: <a href="/user/send_confirmation_email?email=%s">send confirmation email</a>.' % email)
            return None

        if user.verify_password(password):
            self['user_id'] = user.user_id
            self._user = user
            return self._user
        else:
            self.set_status('bad password')
            return None

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

