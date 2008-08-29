"""
The stuff for the base package
"""

import cherrypy

from base import utils

try:
  from django.utils import simplejson
except:
  import simplejson
  
import session
import sys, traceback

FAILURE = "failure"
SUCCESS = "success"

def web(func):
    """
    A decorator that enables cherrypy
    but also that enables filters
    """
    def apply_before_filter(self, *args, **kwargs):
        self.before_filter()
        return func(self, *args, **kwargs)

    return_val = cherrypy.expose(apply_before_filter)
    return_val.expose_resource = True
    return return_val

def json(func):
    """
    A decorator that serializes the output to JSON before returning to the
    web client.
    """
    def convert_to_json(self, *args, **kwargs):
        return utils.to_json(func(self, *args, **kwargs))

    return convert_to_json

class Controller:
    """
    The core controller class, with filter implementation and basic template rendering hooks.
    """
    def render(self, tmpl):
        return template.render(self.__class__.TEMPLATES_DIR + tmpl, 1)
    
    def before_filter(self):
        pass
    
    def user(self):
        return session.get_session().get_user()

    def error(self, msg):
        raise cherrypy.HTTPError(500, msg)
        
    def redirect(self, url):
        raise cherrypy.HTTPRedirect(url)
