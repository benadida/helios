"""
Helios Basic Controllers

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template

import cherrypy, time, logging

try:
  from django.utils import simplejson
except:
  import simplejson

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
    
  @web
  def faq(self):
    return self.render('faq')
                    

class AboutController(Controller):
  TEMPLATES_DIR = HeliosController.TEMPLATES_DIR + 'about/'

  @web
  def index(self):
    return self.render('index')
    
  @web
  def technology(self):
    return self.render('technology')

