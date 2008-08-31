"""
A client-side admin program for Helios

Ben Adida
2008-08-30
"""

from base import oauth, utils
from crypto import algs

import oauthclient

class HeliosClient(object):
  def __init__(self, auth_info, host, port):
    """
    auth_info is consumer_key, ....
    """
    self.consumer = oauth.OAuthConsumer(auth_info['consumer_key'],auth_info['consumer_secret'])
    self.token = oauth.OAuthToken(auth_info['access_token'],auth_info['access_token_secret'])
    self.client = oauthclient.MachineOAuthClient(self.consumer, self.token, host, port)
    
  def get(self, url, parameters = None):
    return self.client.access_resource("GET", url, parameters= parameters)
  
  def post(self, url, parameters = None):
    return self.client.access_resource("POST", url, parameters= parameters)

  def params(self):
    params_json = self.get("/elections/params")
    return algs.ElGamal.fromJSONDict(utils.from_json(params_json))
    
  def election_new(self, name, public_key):
    election_id = self.post("/elections/new_2", {"name" : name, "public_key" : utils.to_json(public_key.toJSONDict())})
    return election_id
    
  def election_set_reg(self, election_id, open_reg=False):
    result = self.post("/elections/%s/set_reg" % election_id, {'open_p' : str(int(open_reg))})
    return result == "SUCCESS"
    
  def election_questions_save(self, election_id, questions):
    result = self.post("/elections/%s/save" % election_id, {'election_json' : utils.to_json(questions)})
    return result == "SUCCESS"
    
  def election_freeze(self, election_id):
    result = self.post("/elections/%s/freeze_2" % election_id, {})
    return result == "SUCCESS"
    
  def open_submit(self, election_id, encrypted_vote, email=None, openid_url=None, name=None, category=None):
    """
    encrypted_vote is a JSON string
    """
    result = self.post("/elections/%s/open_submit" % election_id, {'encrypted_vote' : encrypted_vote, 'email': email,
                                                                  'openid_url' : openid_url, 'name' : name, 'category' :category})
                                                                  
    return result
    
  def set_tally(self, election_id, result, result_proof):
    tally_obj = {'result' : result, 'result_proof' : result_proof}
    tally_obj_json = utils.to_json(tally_obj)
    
    result = self.post("/elections/%s/set_tally" % election_id, {'tally' : tally_obj_json})
    return result == "SUCCESS"

helios = HeliosClient({'consumer_key': 'votehere', 'consumer_secret': 'votehere',
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