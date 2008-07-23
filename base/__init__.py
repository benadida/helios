"""
The stuff for the base package
"""

import cherrypy, simplejson
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
    def convert_to_json(self, *args, **kwargs):
        return simplejson.dumps(func(self, *args, **kwargs), sort_keys = True)

    return convert_to_json

class Controller:
    def render(self, tmpl):
        return template.render(self.__class__.TEMPLATES_DIR + tmpl, 1)
    
    def before_filter(self):
        pass
    
    def user(self):
        return session.get_session().get_user()

    def error(self, msg):
        raise cherrypy.HTTPError(500, msg)
