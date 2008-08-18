"""
The DBObject base class

ben@adida.net
"""

#from DBObjectGAE import *
try:
  from google.appengine.ext import db
  from DBObjectGAE import *
except:
  from DBObjectStandalone import *