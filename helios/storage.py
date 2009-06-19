"""
A storage abstraction for Helios that can be backed either by
Google App Engine, or by Django SQL ORM.

Ben Adida
ben@adida.net
2009-06-18
"""

##
## Elections
##

def election_create(ballot_type, tally_type, election_name, admin, api_client, public_key, private_key):
  pass

def election_get(election_id):
  pass

def elections_get_by_user(user_id, include_archived_p=False):
  pass

##
## Voters
##

def voter_get(election, voter_name):
  pass

def voter_create(election, voter_name, full_name, category):
  pass

def voter_set_encrypted_vote(voter, encrypted_vote):
  pass
  
##
## Trustees
##

def trustee_create(election, user_id):
  pass

def trustees_get_by_election(election):
  pass

