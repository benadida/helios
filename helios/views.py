"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.http import *
from security import *

# Create your views here.
def home(request):
  return HttpResponse("foo")
  
def learn(request):
  return HttpResponse("learn")
  
def faq(request):
  return HttpResponse("faq")
  
def about(request):
  return HttpResponse("about")
  
##
## User
##

def user_home(request):
  return HttpResponse("user home")
  
def user_login(request):
  return HttpResponse("user login")
  
def user_logout(request):
  return HttpResponse("user logout")
  
##
## General election features
##

def election_params(request):
  pass

def election_verifier(request):
  pass

def election_single_ballot_verifier(request):
  pass

def election_js_api(request):
  pass

def election_new(request):
  pass

def election_new_2(request):
  pass
  
def election_new_3(request):
  pass

##
## Specific election features
##

@election_admin
def one_election_keyshares_manage(request, election):
  return HttpResponse("election keyshares %s" % election.id)

@election_admin
def one_election_keyshares_tally_manage(request, election):
  return HttpResponse("election keyshares tally %s" % election.id)
  
@election_view
def one_election(request, election):
  return HttpResponse("election id %s" % election.id)

@election_view
def one_election_view(request, election):
  return HttpResponse("election view %s" % election.id)

@election_admin
def one_election_open_submit(request, election):
  return HttpResponse("election open submit %s" % election.id)

@election_view
def one_election_result(request, election):
  return HttpResponse("election result %s" % election.id)

@election_view
def one_election_result_proof(request, election):
  return HttpResponse("election result proof %s" % election.id)

@election_view
def one_election_get_voter_by_email(request, election):
  return HttpResponse("election get voter by email %s" % election.id)

@election_view
def one_election_get_voter_by_openid(request, election):
  return HttpResponse("election get voter by openid %s" % election.id)

@election_view
def one_election_vote(request, election):
  """
  UI to vote in an election
  """
  return HttpResponse("election vote UI %s" % election.id)

@election_view
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  return HttpResponse("election bboard %s" % election.id)
  
@election_admin
def one_election_set_pk(request, election):
  return HttpResponse("election set pk %s" % election.id)

@election_admin
def one_election_voters_manage(request, election):
  return HttpResponse("election voters manage %s" % election.id)

@election_admin
def one_election_voters_bulk_upload(request, election):
  return HttpResponse("election voters bulk upload %s" % election.id)

@election_admin
def one_election_voters_delete(request, election):
  return HttpResponse("election voters delete %s" % election.id)

@election_admin
def one_election_voters_email(request, election):
  return HttpResponse("election voters email %s" % election.id)

@election_admin
def one_election_set_reg(request, election):
  return HttpResponse("election voters set_reg %s" % election.id)

@election_admin
def one_election_archive(request, election):
  return HttpResponse("election archive %s" % election.id)

@election_admin
def one_election_build(request, election):
  return HttpResponse("election build %s" % election.id)

@election_admin
def one_election_save_questions(request, election):
  return HttpResponse("election save questions %s" % election.id)

@election_admin
def one_election_freeze(request, election):
  return HttpResponse("election freeze %s" % election.id)

@election_admin
def one_election_email_trustees(request, election):
  return HttpResponse("election email trustees %s" % election.id)

@election_admin
def one_election_compute_tally(request, election):
  return HttpResponse("election compute tally %s" % election.id)

@election_admin
def one_election_drive_tally_chunk(request, election):
  return HttpResponse("election drive tally chunk %s" % election.id)

@election_admin
def one_election_drive_tally(request, election):
  return HttpResponse("election drive tally %s" % election.id)

@election_admin
def one_election_set_tally(request, election):
  return HttpResponse("election set tally %s" % election.id)

@election_admin
def one_election_compute_tally_chunk(request, election):
  return HttpResponse("election compute tally chunk %s" % election.id)

# Individual Voters
@election_view
def voter_list(request, election):
  return HttpResponse("voter list for election %s" % election.id)

@election_admin
def voter_add(request, election):
  return HttpResponse("voter add for election %s" % election.id)

@election_view
def one_voter(request, election, voter_id):
  return HttpResponse("one voter for election %s" % election.id)

@election_admin
def one_voter_delete(request, election, voter_id):
  return HttpResponse("voter delete for election %s" % election.id)

@election_view
def one_voter_submit(request, election, voter_id):
  return HttpResponse("voter submit for election %s" % election.id)
  
# Trustees
@election_view
def trustees_list(request, election):
  return HttpResponse("trustees list for election %s" % election.id)

@election_view
def trustee_home(request, election, trustee_email):
  return HttpResponse("trustees home for election %s" % election.id)

@election_view
def trustee_upload_pk(request, election, trustee_email):
  return HttpResponse("trustees upload pk for election %s" % election.id)

@election_view
def trustee_tally(request, election, trustee_email):
  return HttpResponse("trustees tally for election %s" % election.id)

@election_view
def trustee_upload_decryption_factor(request, election, trustee_email):
  return HttpResponse("trustees upload dec factor for election %s" % election.id)

