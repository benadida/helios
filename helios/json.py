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
    def db_type(self):
        return 'text'

    def get_internal_type(self):
        return 'TextField'
        
    def pre_save(self, model_instance, add):
        value = getattr(model_instance, self.attname, None)
        return dumps(value)
    
    def contribute_to_class(self, cls, name):
        super(JSONField, self).contribute_to_class(cls, name)
        #dispatcher.connect(self.post_init, signal=signals.post_init, sender=cls)
        
        def get_json(model_instance):
            return dumps(getattr(model_instance, self.attname, None))
        setattr(cls, 'get_%s_json' % self.name, get_json)
    
        def set_json(model_instance, json):
            return setattr(model_instance, self.attname, loads(json))
        setattr(cls, 'set_%s_json' % self.name, set_json)
    
    def post_init(self, instance=None):
        value = self.value_from_object(instance)
        if (value):
            setattr(instance, self.attname, loads(value))
        else:
            setattr(instance, self.attname, None)


class JSONObject(object):
  def toJSONDict(self):
    raise Exception("must override this")
  
  def toJSON(self):
    # FIXME: factor in the JSON_FIELDS for the class
    return json.dumps(self.toJSONDict())