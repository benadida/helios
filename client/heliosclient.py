"""
The Helios Client

Ben Adida
2008-08-30
"""

import oauthclient
from helios import utils, oauth
from crypto import algs, electionalgs

class HeliosClient(object):
  def __init__(self, auth_info, host, port, prefix=""):
    """
    auth_info is consumer_key, ....
    """
    self.consumer = oauth.OAuthConsumer(auth_info['consumer_key'],auth_info['consumer_secret'])
    self.token = oauth.OAuthToken(auth_info['consumer_key'],auth_info['consumer_secret'])
    self.client = oauthclient.MachineOAuthClient(self.consumer, self.token, host, port)
    self.prefix = prefix
    
  def get(self, url, parameters = None):
    print "getting " + self.prefix + url
    return self.client.access_resource("GET", self.prefix + url, parameters= parameters)
  
  def post(self, url, parameters = None):
    print "posting " + self.prefix + url
    result = self.client.access_resource("POST", self.prefix + url, parameters= parameters)
    return result

  def params(self):
    params_json = self.get("/elections/params")
    return algs.ElGamal.fromJSONDict(utils.from_json(params_json))
    
  def election_new(self, name, public_key):
    election_id = self.post("/elections/new_3", {"name" : name, "public_key" : utils.to_json(public_key.toJSONDict())})
    return election_id
    
  def election_get(self, election_id):
    return electionalgs.Election.fromJSONDict(utils.from_json(self.get("/elections/%s/" % election_id)))
    
  def election_set_reg(self, election_id, open_reg=False):
    result = self.post("/elections/%s/set_reg" % election_id, {'open_p' : str(int(open_reg))})
    return result == "SUCCESS"
    
  def election_questions_save(self, election_id, questions):
    result = self.post("/elections/%s/save_questions" % election_id, {'questions_json' : utils.to_json(questions)})
    return result == "SUCCESS"
    
  def election_freeze(self, election_id):
    result = self.post("/elections/%s/freeze" % election_id, {})
    return result == "SUCCESS"
    
  def open_submit(self, election_id, encrypted_vote, email=None, openid_url=None, name=None, category=None):
    """
    encrypted_vote is a JSON string
    """
    parameters = {'encrypted_vote' : encrypted_vote}
    if email: parameters['email']= email
    if openid_url: parameters['openid_url'] = openid_url
    if name: parameters['name'] = name
    if category: parameters['category'] = category

    result = self.post("/elections/%s/open_submit" % election_id, parameters)
                                                                  
    return result
    
  def set_tally(self, election_id, result, result_proof):
    tally_obj = {'result' : result, 'result_proof' : result_proof}
    tally_obj_json = utils.to_json(tally_obj)
    
    result = self.post("/elections/%s/set_tally" % election_id, {'tally' : tally_obj_json})
    return result == "SUCCESS"