"""
List Voters

usage:
python client/listvoters.py HELIOS_SERVER ELECTION_ID
"""

from base import utils
from crypto import algs, electionalgs
from client import heliosclient

import sys

try:
  import simplejson
except:
  from django.utils import simplejson

HELIOS_SERVER = sys.argv[1]
ELECTION_ID = sys.argv[2]

def open_and_read_file(file_path):
  the_file = open(file_path, "r")
  the_content = the_file.read()
  the_file.close()
  return the_content

# bogus API key, not needed
api_key = utils.from_json("""{"consumer_key": "foo", "consumer_secret": "foo", "access_token": "bar", "access_token_secret" : "bar"}""")

# instantiate the client
helios = heliosclient.HeliosClient(api_key,
                        host = HELIOS_SERVER,
                        port = 80)

# load the election 
election = helios.election_get(ELECTION_ID)

# download the voters (store them all in RAM, why not)
last_voter_id = None
LIMIT = 490
voters = []

while True:
  print "LAST VOTER ID is %s" % str(last_voter_id)

  new_voters = helios.election_voters(ELECTION_ID, after=last_voter_id, limit=LIMIT, with_vote=False)
  
  print "got %s voters " % len(new_voters)

  # append to existing voter list
  voters += new_voters
  
  if len(new_voters) < LIMIT:
    break
  
  last_voter_id = new_voters[len(new_voters) - 1]['voter_id']

print "got %s total voters " % len(voters)
  
voter_with_vote_list = [v for v in voters if v['vote_hash'] != None]

print "%s cast vote(s)" % str(len(voter_with_vote_list))

# print out the voters
print "\n\n\n"
for v in voters:
  if not v['vote_hash']:
    v['vote_hash'] = '--'
  print "\"%s\",\"%s\",\"%s\"" % (v['name'], v['email'], v['vote_hash'])
