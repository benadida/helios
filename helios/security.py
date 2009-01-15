"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

# nicely update the wrapper function
from functools import update_wrapper

from django.http import *
from django.core.exceptions import *
from django.conf import settings

from models import *

import oauth
    
# get authenticated user
def get_user(request):
  if request.user.is_authenticated():
    return request.user
  else:
    return None

##
## OAuth and API clients
##

class OAuthDataStore(oauth.OAuthDataStore):
  def __init__(self):
    pass
      
  def lookup_consumer(self, key):
    c = APIClient.objects.get(consumer_key = key)
    return oauth.OAuthConsumer(c.consumer_key, c.consumer_secret)

  def lookup_token(self, oauth_consumer, token_type, token):
    if token_type != 'access':
      raise NotImplementedError

    c = APIClient.objects.get(consumer_key = oauth_consumer.key)
    return oauth.OAuthToken(c.consumer_key, c.consumer_secret)

  def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
    """
    FIXME this to actually check for nonces
    """
    return None

# create the oauth server
OAUTH_SERVER = oauth.OAuthServer(OAuthDataStore())
OAUTH_SERVER.add_signature_method(oauth.OAuthSignatureMethod_HMAC_SHA1())
    
def get_api_client(request):
  parameters = request.POST.copy()
  parameters.update(request.GET)
  
  if request.META.has_key('SCRIPT_NAME'):
    full_url = request.META['SCRIPT_NAME'] + request.path_info
  else:
    full_url = request.path_info
    
  oauth_request = oauth.OAuthRequest.from_request(request.method, full_url, headers= request.META,
                                                  parameters=parameters, query_string=None)
                                                  
  if not oauth_request:
    return None
    
  try:
    consumer, token, params = OAUTH_SERVER.verify_request(oauth_request)
    return APIClient.objects.get(consumer_key = consumer.key)
  except oauth.OAuthError:
    return None
  
# decorator for login required
def login_required(func):
  def login_required_wrapper(request, *args, **kw):
    if not (get_user(request) or get_api_client(request)):
      return HttpResponseRedirect(settings.LOGIN_URL)
  
    return func(request, *args, **kw)

  return update_wrapper(login_required_wrapper, func)
  
# decorator for admin required
def admin_required(func):
  def admin_required_wrapper(request, *args, **kw):
    user = get_user(request)
    if not user or not user.is_staff:
      raise PermissionDenied()
      
    return func(request, *args, **kw)

  return update_wrapper(admin_required_wrapper, func)

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
  
def api_client_can_admin_election(api_client, election):
  return election.api_client == api_client and api_client != None
  
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
  
