
# see if this is google app engine or not
try:
  from google.appengine.ext.webapp import util
  
  #from gaemodels import *
except:
  from djangomodels import *