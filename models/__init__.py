"""
The Models for Helios.

First the generic stuff, then the extension
"""

#from modelsGAE import *
try:
  from google.appengine.ext import db
  from modelsGAE import *
except:
  from modelsStandalone import *