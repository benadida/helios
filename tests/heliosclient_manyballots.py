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

all_votes = []

plaintext_choices = [0, 0]

# create 1000 ballots
for i in range(100):
  # random choice for the ballot
  choice = algs.Utils.random_mpz_lt(1000) % 2
  
  ballot = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[choice]])
  
  # count the plaintexts
  plaintext_choices[choice] += 1
  
  print "one ballot"
  print "ballot hash: %s" % ballot.get_hash()

  # open submit it
  print "ballot #" + str(i) + " id: %s" % helios.open_submit(election_id, utils.to_json(ballot.toJSONDict()), 'ben' + str(i) + '@adida.net', None, 'Ben Adida - ' + str(i), 'Category ' + str(i%3 + 1))
  all_votes.append(ballot)

# the secret key
sk = kp.sk

# start tallying
tally = election.init_tally()

print "adding all votes"

tally.add_vote_batch(all_votes)

print "decrypting and proving"

result, proof = tally.decrypt_and_prove(sk)
helios.set_tally(election_id, result, proof)

print "expected tally is:"
print plaintext_choices
print "\n"
print "computed tally is: "
print result
