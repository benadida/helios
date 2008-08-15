"""
Helios Basic Controllers

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template, utils

import cherrypy, time, logging
from django.utils import simplejson

class HeliosController(Controller):
  """
  Top-Level Helios controller
  """
  TEMPLATES_DIR = ''

  @web
  def index(self):
    return self.render('index')

  @web
  def learn(self):
    return self.render('learn')
                    

class AboutController(Controller):
  TEMPLATES_DIR = HeliosController.TEMPLATES_DIR + 'about/'

  @web
  def index(self):
    return self.render('index')
    
  @web
  def technology(self):
    return self.render('technology')

