"""
The DBObject base class

Database objects that could be DB-backed, or GAE backed. For now, just GAE.

This needs more work to be much more generic.

ben@adida.net
"""

import utils

try:
  from django.utils import simplejson
except:
  import simplejson
  
import datetime

from google.appengine.ext import db

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

class DBObject(db.Model):

    # GAE get_id
    def get_id(self):
        return self.key()

    @classmethod
    def selectById(cls, key_value):
        return cls.get(key_value)
        
    @classmethod
    def selectByKey(cls, key_name, key_value):
      return cls.selectByKeys({key_name: key_value})
    
    @classmethod
    def selectByKeys(cls, keys):
        # GAE
        all_values= cls.selectAllByKeys(keys)
        if len(all_values) == 0:
          return None
        else:
          return all_values[0]

    @classmethod
    def selectAll(cls, order_by = None, offset = None, limit = None):
        # GAE query
        query = cls.all()
        
        # order
        if order_by:
            query.order(order_by)
        
        return query.fetch(limit=limit or 1000, offset=offset or 0)

    @classmethod
    def selectAllByKey(cls, key_name, key_value, order_by = None, offset = None, limit = None):
        keys = dict()
        keys[key_name] = key_value
        return cls.selectAllByKeys(keys, order_by, offset, limit)
        
    @classmethod
    def selectAllByKeys(cls, keys, order_by = None, offset = None, after = None, limit = None):
        # unicode
        for k,v in keys.items():
            keys[k] = to_utf8(v)

        # GAE query
        query = cls.all()

        # order
        if order_by:
          query.order(order_by)

        # conditions
        for k,v in keys.items():
          query.filter('%s' % k, v)
          
        # after
        if order_by and after:
          query.filter('%s > ' % order_by, after)

        return query.fetch(limit=limit or 1000, offset=offset or 0)        

    def _load_from_row(self, row, extra_fields=[]):

        prepared_row = self._prepare_object_values(row)
        
        for field in self.FIELDS:
            # unicode
            self.__dict__[field] = from_utf8(prepared_row[field])

        for field in extra_fields:
            # unicode
            self.__dict__[field] = from_utf8(prepared_row[field])

    def insert(self):
        """
        Insert a new object, but only if it hasn't been inserted yet
        """
        self.save()

    def update(self):
        """
        Update an object
        """
        # GAE
        self.save()

    # DELETE inherited from GAE
            
    @classmethod
    def multirow_to_array(cls, multirow, extra_fields=[]):
        objects = []

        if multirow == None:
            return objects

        for row in multirow:
            one_object = cls()
            one_object._load_from_row(row, extra_fields)
            objects.append(one_object)

        return objects
    
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
        return utils.to_json(self.toJSONDict())
