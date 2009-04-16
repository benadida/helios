"""
JSON stuff, including

A JSON field for Django, taken from
http://www.djangosnippets.org/snippets/377/

A JSON Object for JSON serialization of objects

Ben Adida
ben@adida.net
2008-12-19
"""

import datetime
from django.db import models
from django.db.models import signals
from django.conf import settings
from django.utils import simplejson as json
from django.dispatch import dispatcher

# not currently used (Ben)
class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, datetime.time):
            return obj.strftime('%H:%M:%S')
        return json.JSONEncoder.default(self, obj)

##
## changed (Ben) to just use simplejson.dumps 2008-12-19
##
def dumps(data):
    #return JSONEncoder().encode(data)
    return json.dumps(data, sort_keys=True)
    
def loads(str):
    return json.loads(str, encoding=settings.DEFAULT_CHARSET)
    
class JSONField(models.TextField):
    __metaclass__ = models.SubfieldBase
  
    def __init__(self, *args, **kwargs):
      if kwargs.has_key('json_obj_class'):
        json_obj_class = kwargs['json_obj_class']
        del kwargs['json_obj_class']
      else:
        json_obj_class = None
        
      super(JSONField, self).__init__(self, *args, **kwargs)

      self.__json_obj_class = json_obj_class
      
    def db_type(self):
        return 'text'

    def get_internal_type(self):
        return 'TextField'
        
    def get_db_prep_value(self, value):
        if not value:
          return None
          
        if self.__json_obj_class:
          return dumps(value.toJSONDict())
        else:
          return dumps(value)
 
    def to_python(self, value):
        # already pythonized?
        if self.__json_obj_class and isinstance(value, self.__json_obj_class):
          return value
          
        if not self.__json_obj_class and (isinstance(value, dict) or isinstance(value, list)):
          return value
        
        if value:
          if self.__json_obj_class:
            return self.__json_obj_class.fromJSONDict(loads(value))
          else:
            return loads(value)
        else:
          return None


class JSONObject(object):
  def toJSONDict(self, extra_fields = []):
      # a helper recursive procedure to navigate down the items
      # even if they don't have a toJSONDict() method
      def toJSONRecurse(item):
          if type(item) == int or type(item) == bool or hasattr(item, 'encode') or not item:
              return item

          if hasattr(item,'toJSONDict'):
              return item.toJSONDict()
          
          if type(item) == dict:
              new_dict = dict()
              for k in item.keys():
                  new_dict[k] = toJSONRecurse(item[k])
              return new_dict

          if hasattr(item,'__iter__'):
              return [toJSONRecurse(el) for el in item]
              
          return str(item)
          
      # limit the fields to just JSON_FIELDS if it exists
      json_dict = dict()
      if hasattr(self.__class__,'JSON_FIELDS'):
          keys = self.__class__.JSON_FIELDS + extra_fields
      else:
          keys = extra_fields
      
      # go through the keys and recurse down each one
      for f in keys:
          ## FIXME: major hack here while I figure out how to dynamically get the right field
          if hasattr(self, f):
              json_dict[f] = toJSONRecurse(getattr(self, f))
          else:
              if self.__dict__.has_key(f):
                  json_dict[f] = toJSONRecurse(self.__dict__[f])
              else:
                  continue
          

      return json_dict
      
  def toJSON(self):
    # FIXME: factor in the JSON_FIELDS for the class
    return dumps(self.toJSONDict())