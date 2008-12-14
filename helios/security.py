"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

# nicely update the wrapper function
from functools import update_wrapper

class Election(object):
  def __init__(self, id):
    self.id = id
    
def election_view(func):
  def election_view_wrapper(request, election_id, *args, **kw):
    # FIXME: load the actual election
    election = Election(election_id)
    
    return func(request, election, *args, **kw)

  return update_wrapper(election_view_wrapper, func)

def election_admin(func):
  def election_admin_wrapper(request, election_id, *args, **kw):
    # FIXME: load the actual election
    election = Election(election_id)

    return func(request, election, *args, **kw)

  return update_wrapper(election_admin_wrapper, func)
