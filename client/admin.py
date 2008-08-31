"""
A client-side admin program for Helios

Ben Adida
2008-08-30
"""

import heliosclient

helios = heliosclient.HeliosClient({'consumer_key': 'votehere', 'consumer_secret': 'votehere',
                        'access_token': '123', 'access_token_secret' : '123'},
                        host = 'localhost',
                        port = 8082)

# get the El Gamal Parameters
params = helios.params()

# generate a keypair
kp = params.generate_keypair()

# create the election
election_id = helios.election_new("foo", kp.pk)

print "election id is: " + election_id

# set open reg
print helios.election_set_reg(election_id, open_reg= True)

# freeze it
print helios.election_freeze(election_id)

# open submit a couple of votes
print helios.open_submit(election_id, '{"foo":"bar"}', 'ben@adida.net', None, 'Ben Adida', 'Foo Category')
print helios.open_submit(election_id, '{"foo":"bazzz"}', 'ben2@adida.net', 'http://benadida.myopenid.com', 'Ben2 Adida', 'Bar Category')