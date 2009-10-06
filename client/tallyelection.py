"""
Tally Election

usage:
python client/tallyelection.py HELIOS_SERVER ELECTION_ID API_KEY_FILE.json SECRET_KEY_FILE.txt
"""

from base import utils
from crypto import algs, electionalgs
from client import heliosclient

import sys

HELIOS_SERVER = sys.argv[1]
ELECTION_ID = sys.argv[2]
API_KEY_FILE = sys.argv[3]
SECRET_KEY_FILE = sys.argv[4]

def open_and_read_file(file_path):
  the_file = open(file_path, "r")
  the_content = the_file.read()
  the_file.close()
  return the_content

# parse the json for api keys
api_key = utils.from_json(open_and_read_file(API_KEY_FILE))

# instantiate the client
helios = heliosclient.HeliosClient(api_key,
                        host = HELIOS_SERVER,
                        port = 80)

# load the election 
election = helios.election_get(ELECTION_ID)

# download the voters (store them all in RAM, why not)
last_voter_id = None
LIMIT = 100
voters = []

while True:
  print "LAST VOTER ID is %s" % str(last_voter_id)

  new_voters = helios.election_voters(ELECTION_ID, after=last_voter_id, limit=LIMIT, with_vote=True)
  
  # append to existing voter list
  voters += new_voters
  
  if len(new_voters) < LIMIT:
    break
    
  last_voter_id = new_voters[len(new_voters) - 1]['voter_id']
  
vote_list = [v['vote'] for v in voters if v['vote'] != None]

print "%s cast vote(s)" % str(len(vote_list))

# tally them
tally = election.init_tally()

# set the tally to 0s to stop voting
helios.set_tally(ELECTION_ID, [[0,0]], None)

import pdb; pdb.set_trace()

for v in vote_list:
  enc_ballot = electionalgs.EncryptedVote.fromJSONDict(v)
  tally.add_vote(enc_ballot)
  
pdb.set_trace()

# secret key load
sk = algs.EGSecretKey.fromJSONDict(utils.from_json(open_and_read_file(SECRET_KEY_FILE)))

# decrypt and prove
result, proof = tally.decrypt_and_prove(sk)

print result
print proof

pdb.set_trace()

# upload result
helios.set_tally(ELECTION_ID, result, proof)

