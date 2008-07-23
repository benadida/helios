"""
Helios Site

Ben Adida (ben@adida.net)
"""

from base import session
session.LOGIN_URL = '/user/'

import cherrypy
from controllers import *

root_controller = basic.HeliosController()
root_controller.about = basic.AboutController()
root_controller.user = user.UserController()
root_controller.elections = election.ElectionController()

root = cherrypy.tree.mount(root_controller, '/')

