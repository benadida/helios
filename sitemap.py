"""
Helios Site

Ben Adida (ben@adida.net)
"""

from base import session
session.LOGIN_URL = '/user/'

# setup oauth
import models
session.Session.setup_oauth(models.OAuthDataStore())

import cherrypy
from controllers import *


# mount points for various controllers
root_controller = basic.HeliosController()
root_controller.about = basic.AboutController()
root_controller.user = user.UserController()
root_controller.elections = election.ElectionController()
root_controller.admin = admin.AdminController()

root = cherrypy.tree.mount(root_controller, '/')

