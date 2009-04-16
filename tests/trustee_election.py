"""
A test to set up an election with trustees
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
                        host = "localhost",
                        port = 8000,
                        )

# get the El Gamal Parameters
params = helios.params()

# generate three keypairs
kp_1 = params.generate_keypair()
kp_2 = params.generate_keypair()
kp_3 = params.generate_keypair()

print "3 keypairs generated"

# generate proofs
pok_1 = kp_1.sk.prove_sk(algs.DLog_challenge_generator)
pok_2 = kp_2.sk.prove_sk(algs.DLog_challenge_generator)
pok_3 = kp_3.sk.prove_sk(algs.DLog_challenge_generator)

# generate the full PK
full_pk = kp_1.pk * kp_2.pk * kp_3.pk

# create the election remotely
election_id = helios.election_new("Remote Trustee Test", trustee_list=['trustee1@adida.net', 'trustee2@adida.net', 'trustee3@adida.net'])

# upload the keyshares and Poks
helios.election_set_trustee_pk(election_id, 'trustee1@adida.net', kp_1.pk, pok_1)
helios.election_set_trustee_pk(election_id, 'trustee2@adida.net', kp_2.pk, pok_2)
helios.election_set_trustee_pk(election_id, 'trustee3@adida.net', kp_3.pk, pok_3)

# set the PK
helios.election_set_pk(election_id, full_pk)

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
ballot_2 = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[1]])
ballot_3 = electionalgs.EncryptedVote.fromElectionAndAnswers(election, [[0]])

print "created 3 ballots"

print "ballot #1 hash: %s" % ballot_1.get_hash()
print "ballot #2 hash: %s" % ballot_2.get_hash()
print "ballot #3 hash: %s" % ballot_3.get_hash()

# open submit the three votes
print "ballot #1 id: %s" % helios.open_submit(election_id, utils.to_json(ballot_1.toJSONDict()), 'ben@adida.net', None, 'Ben Adida', 'Foo Category')
print "ballot #2 id: %s" % helios.open_submit(election_id, utils.to_json(ballot_2.toJSONDict()), 'ben2@adida.net', None, 'Ben2 Adida', 'Foo Category')
print "ballot #3 id: %s" % helios.open_submit(election_id, utils.to_json(ballot_3.toJSONDict()), 'ben3@adida.net', None, 'Ben3 Adida', 'Bar Category')

# do homomorphic encrypted tallying
tally = election.init_tally()
tally.add_vote_batch([ballot_1, ballot_2, ballot_3])

# get decryption of shares for the three keys

# upload the shares and proofs

# compute the full tally

# upload the full tally

