"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

# nicely update the wrapper function
from functools import update_wrapper

from django.http import *

from models import *
    
# get authenticated user
def get_user(request):
  if request.user.is_authenticated():
    return request.user
  else:
    return None

# decorator for views that pertain to an election
def election_view(func):
  def election_view_wrapper(request, election_id, *args, **kw):
    election = Election.objects.get(election_id = election_id)
    
    return func(request, election, *args, **kw)

  return update_wrapper(election_view_wrapper, func)

def user_can_admin_election(user, election):
  return election.admin == user
  
# decorator for checking election admin access
def election_admin(func):
  def election_admin_wrapper(request, election_id, *args, **kw):
    election = Election.objects.get(election_id = election_id)

    if not user_can_admin_election(get_user(request), election):
      raise PermissionDenied()

    return func(request, election, *args, **kw)

  return update_wrapper(election_admin_wrapper, func)
