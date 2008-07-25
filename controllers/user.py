"""
Helios User Controller

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template
from crypto import algs
from models import models as do

import cherrypy, simplejson, time, logging

from google.appengine.api import users

# the basic controllers
import basic

class UserController(Controller):
  """
  Controller for managing a user's elections.
  """
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'user/'

  @web
  def index(self):
    """
    Display user homepage.
    """
    user = self.user()

    if user:
      elections = do.Election.getByAdmin(user)
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
  
