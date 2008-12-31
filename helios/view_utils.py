"""
Utilities for all views

Ben Adida (12-30-2008)
"""

from django.template import Context, Template, loader
from django.http import *

from security import *

##
## BASICS
##

SUCCESS = HttpResponse("SUCCESS")

##
## template abstraction
##
def render_template(request, template_name, vars = {}):
  t = loader.get_template(template_name + '.html')
  
  vars_with_user = vars.copy()
  vars_with_user['user'] = get_user(request)
  vars_with_user['utils'] = utils
  c = Context(vars_with_user)
  return HttpResponse(t.render(c))
  
def render_json(json_txt):
  return HttpResponse(json_txt)

# decorator
def json(func):
    """
    A decorator that serializes the output to JSON before returning to the
    web client.
    """
    def convert_to_json(self, *args, **kwargs):
      return render_json(utils.to_json(func(self, *args, **kwargs)))

    return convert_to_json