"""
Helios User Controller

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template
from crypto import algs
import models as do

import cherrypy, time, logging

try:
  from django.utils import simplejson
except:
  import simplejson

try:
  from google.appengine.api import users
except:
  pass

# the basic controllers
import basic

class UserController(Controller):
  """
  Controller for managing a user's elections.
  """
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'user/'

  @web
  def index(self, include_archived=False):
    """
    Display user homepage.
    """
    user = self.user()

    if user:
      elections = do.Election.getByAdmin(user, include_archived)
      status = session.get_status()
      return self.render('index')
    else:
      raise cherrypy.HTTPRedirect(users.create_login_url("/user"))

  @web
  def login(self, email, password):
    """
    Perform login.
    """
    session.get_session().login(email,password)
    raise cherrypy.HTTPRedirect('./')

  @web
  def logout(self):
    """
    Perform logout.
    """
    session.logout()
    session.set_status('You are now logged out.')
    raise cherrypy.HTTPRedirect(users.create_logout_url('/user/'))
  
