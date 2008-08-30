"""
Helios User Controller

Ben Adida (ben@adida.net)
"""

from base import *
from base import session, Controller, template
import models as do

import cherrypy, time, logging

try:
  from google.appengine.api import users
except:
  pass

# the basic controllers
import basic

class AdminController(Controller):
  """
  Controller for administering Helios.
  """
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'admin/'

  @web
  @session.admin_protect
  def index(self):
    """
    Display admin homepage.
    """
    return self.render('index')
    
  @web
  @session.admin_protect
  def clients(self):
    """
    Display API clients
    """
    clients = do.APIClient.selectAll()
    return self.render('clients')
  
  @web
  @session.admin_protect
  def client_new(self, consumer_key, consumer_secret, access_token, access_token_secret):
    new_client = do.APIClient()
    new_client.consumer_key = consumer_key
    new_client.consumer_secret = consumer_secret
    new_client.access_token = access_token
    new_client.access_token_secret = access_token_secret
    new_client.save()
    self.redirect("./")
    
