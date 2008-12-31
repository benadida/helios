"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

# nicely update the wrapper function
from functools import update_wrapper

from django.http import *

from models import *

from django.core.exceptions import *
    
# get authenticated user
def get_user(request):
  if request.user.is_authenticated():
    return request.user
  else:
    return None

#
# some common election checks
#
def do_election_checks(election, props):
  # frozen
  if props.has_key('frozen'):
    frozen = props['frozen']
  else:
    frozen = None
  
  # newvoters (open for registration)
  if props.has_key('newvoters'):
    newvoters = props['newvoters']
  else:
    newvoters = None
  
  # frozen check
  if frozen != None:
    if frozen and not election.frozen_at:
      raise PermissionDenied()
    if not frozen and election.frozen_at:
      raise PermissionDenied()
    
  # open for new voters check
  if newvoters != None:
    import pdb; pdb.set_trace()
    if election.can_add_voters() != newvoters:
      raise PermissionDenied()

  
# decorator for views that pertain to an election
# takes parameters:
# frozen - is the election frozen
# newvoters - does the election accept new voters
def election_view(**checks):
  
  def election_view_decorator(func):
    def election_view_wrapper(request, election_id, *args, **kw):
      election = Election.objects.get(election_id = election_id)
    
      # do checks
      do_election_checks(election, checks)
    
      return func(request, election, *args, **kw)

    return update_wrapper(election_view_wrapper, func)
    
  return election_view_decorator

def user_can_admin_election(user, election):
  return election.admin == user
  
# decorator for checking election admin access, and some properties of the election
# frozen - is the election frozen
# newvoters - does the election accept new voters
def election_admin(**checks):
  
  def election_admin_decorator(func):
    def election_admin_wrapper(request, election_id, *args, **kw):
      election = Election.objects.get(election_id = election_id)

      if not user_can_admin_election(get_user(request), election):
        raise PermissionDenied()
        
      # do checks
      do_election_checks(election, checks)
        
      return func(request, election, *args, **kw)

    return update_wrapper(election_admin_wrapper, func)
    
  return election_admin_decorator
  
