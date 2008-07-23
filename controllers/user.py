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
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'user/'

  @web
  def index(self):
    user = self.user()

    if user:
      elections = do.Election.getByAdmin(user)
      status = session.get_status()
      return self.render('index')
    else:
      raise cherrypy.HTTPRedirect(users.create_login_url("/user"))

  @web
  def login(self, email, password):
    session.get_session().login(email,password)
    raise cherrypy.HTTPRedirect('./')

  @web
  def logout(self):
    session.logout()
    session.set_status('You are now logged out.')
    raise cherrypy.HTTPRedirect(users.create_logout_url('/user/'))
    
  @web
  def register(self):
    return self.render('register')

  @web
  def register_2(self, email, name, password, password2):
    if password != password2:
      self.error('passwords do not match')
    user = do.User(email=email, name=name)
    user.set_password(password)
    user.insert()
    session.get_session().set_user(user)

    self.send_confirmation_email(email)
    
  @web
  def send_confirmation_email(self, email):
    user = do.User.select_by_email(email)

    if user:
      confirmation_url = config.webroot + ('/user/confirm?email=%s&code=%s' % (user.email, user.verification_code))
    
      mail.simple_send([user.name],[user.email], "Helios", "system@heliosvoting.org", "user email confirmation", """

You registered at http://heliosvoting.org with email %s.

To confirm your registration, click the following link:

%s

-Helios
""" % (user.email, confirmation_url))

      session.get_session().set_status('An email confirmation has been sent to you. Check your email!')
    raise cherrypy.HTTPRedirect('./')

  @web
  def confirm(self, email, code):
    user = do.User.select_by_email(email)

    if user.verification_code == code:
      user.verified_p = True
      user.update()
      return self.render("confirm")
    else:
      raise cherrypy.HTTPRedirect('./')
  
