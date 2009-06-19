"""
A storage abstraction for Helios that can be backed either by
Google App Engine, or by Django SQL ORM.

Ben Adida
ben@adida.net
2009-06-18
"""

from models import *

##
## Elections
##

def election_create(ballot_type, tally_type, election_name, admin, api_client, public_key, private_key):
  return  Election.objects.create(ballot_type = ballot_type, tally_type = tally_type, name = election_name,
                      admin = admin, api_client= api_client, public_key = public_key, private_key = private_key)

def election_get(election_id):
  pass

def elections_get_by_user(user_id, include_archived=False):
  if include_archived:
    return Election.objects.filter(admin = user_id)
  else:
    return Election.objects.filter(admin = user_id, archived_at = None)

def election_update(election):
  pass

##
## Voters
##

def voter_get(election, voter_type, voter_id):
  # FIXME
  return Voter.objects.get(election = election, email = voter_id).toJSONDict()

def voter_create(election, voter_type, voter_id, name, category):
  pass

def voter_set_encrypted_vote(voter, encrypted_vote):
  pass

def voters_get(election, after, limit):
  pass

def voter_delete(voter):
  pass

def voter_update(voter):
  voter.save()
  
##
## Trustees
##

def trustee_create(election, user_id):
  keyshare = KeyShare.objects.create(election = election, email = user_id)
  keyshare.generate_password()
  keyshare.save()
  return keyshare

def trustees_get(election):
  return election.get_keyshares()

def trustee_update(trustee):
  pass