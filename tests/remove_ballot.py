"""
Some tests of Helios Client

Variables at the beginning
"""

# give the base path for importing
import sys
sys.path.append('../')

from helios import utils
from crypto import algs, electionalgs
from client import heliosclient

# instantiate the client
# modify variables here
helios = heliosclient.HeliosClient({'consumer_key': 'test', 'consumer_secret': '123'},
#                        host = '79.125.5.192',
                        host = "localhost",
                        port = 8000,
#                         port = 80,
#                        prefix = "/helios"
                        )

print "headers:\n"
print helios.get_test()

# get the El Gamal Parameters
params = helios.params()

# generate a keypair
kp = params.generate_keypair()

# create the election remotely
election_id = helios.election_new("Remote Test", kp.pk)

print "election id is: " + election_id

# set open reg
helios.election_set_reg(election_id, open_reg= True)

# set questions
questions = [{"answers": ["ice-cream", "cake"], "min": 1, "max": 1, "question": "ice-cream or cake?", "short_name": "dessert"}]
helios.election_questions_save(election_id, questions)

# freeze it
helios.election_freeze(election_id)

print "election questions set and frozen"

# get the election
election = helios.election_get(election_id)
print "election hash is %s" % election.hash

ballot = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[1]])
print "ballot hash: %s" % ballot.get_hash()

# open submit it
print helios.open_submit(election_id, utils.to_json(ballot.toJSONDict()), 'ben@adida.net', None, 'Ben Adida', '')

# open submit clear it
print helios.open_submit(election_id, 'null', 'ben@adida.net', None, 'Ben Adida', '')
