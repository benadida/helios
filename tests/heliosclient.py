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
#                        host = '174.129.241.146',
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

# create three ballots
ballot_1 = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[1]])
print "one ballot"
ballot_2 = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[1]])
print "two ballots"
ballot_3 = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[0]])

print "created 3 ballots"

print "ballot #1 hash: %s" % ballot_1.get_hash()
print "ballot #2 hash: %s" % ballot_2.get_hash()
print "ballot #3 hash: %s" % ballot_3.get_hash()

# open submit the three votes
print "ballot #1 id: %s" % helios.open_submit(election_id, utils.to_json(ballot_1.toJSONDict()), 'ben@adida.net', None, 'Ben Adida', 'Foo Category')
print "ballot #2 id: %s" % helios.open_submit(election_id, utils.to_json(ballot_2.toJSONDict()), 'ben2@adida.net', None, 'Ben2 Adida', 'Foo Category')
print "ballot #3 id: %s" % helios.open_submit(election_id, utils.to_json(ballot_3.toJSONDict()), 'ben3@adida.net', None, 'Ben3 Adida', 'Bar Category')

# the secret key
sk = kp.sk

# start tallying
tally = election.init_tally()

tally.add_vote_batch([ballot_1, ballot_2, ballot_3])

result, proof = tally.decrypt_and_prove(sk)
helios.set_tally(election_id, result, proof)

print "tally is: "
print result
