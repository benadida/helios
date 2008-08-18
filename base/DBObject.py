"""
The DBObject base class

ben@adida.net
"""

def from_utf8(string):
    if type(string) == str:
        return string.decode('utf-8')
    else:
        return string
    
def to_utf8(string):
    if type(string) == unicode:
        return string.encode('utf-8')
    else:
        return string

#from DBObjectGAE import *
try:
  from google.appengine.ext import db
  from DBObjectGAE import *
except:
  from DBObjectStandalone import *