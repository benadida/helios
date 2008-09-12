"""
Base stuff for all models
"""

#from base import utils
from base.DBObject import DBObject
from base import utils, oauth, session

try:
  from django.utils import simplejson
except:
  import simplejson
  
import datetime, logging

from crypto import algs, electionalgs

import models

class ElectionBase(DBObject):
  # when JSON'ified
  JSON_FIELDS = ['election_id', 'name', 'pk', 'questions', 'voters_hash', 'openreg', 'voting_starts_at', 'voting_ends_at']
  
  def toJSONDict(self):
    self.pk = self.get_pk()
    self.questions = self.get_questions()
    
    # depending on whether the election supports open registration
    # we could have openreg in there all the time, but for backwards compatibility
    # with existing elections, let's not include it.
    if self.openreg_enabled:
      self.openreg = True
    else:
      self.voters_hash = self.get_voters_hash()
      
    return DBObject.toJSONDict(self)

  def save_dict(self, d):
    self.questions_json = utils.to_json(d['questions'])
    self.update()
    
  def toElection(self):
    """
    Transforms to a standalone election object, independent of storage
    """
    return electionalgs.Election.fromJSONDict(self.toJSONDict())

  def save_questions(self, questions):
    self.questions_json = utils.to_json(questions)
    self.update()
    
  def get_questions(self):
    return utils.from_json(self.questions_json) or []
    
  def set_pk(self, pk):
    self.public_key_json = utils.to_json(pk.toJSONDict())

  def set_sk(self, sk):
    self.private_key_json = utils.to_json(sk.to_dict())

  def get_pk(self):
    if not self.public_key_json: return None
    return algs.EGPublicKey.fromJSONDict(utils.from_json(self.public_key_json))
    
  def get_sk(self):
    if not self.private_key_json: return None
    return algs.EGSecretKey.fromJSONDict(utils.from_json(self.private_key_json))

  def get_voters(self, category=None, after=None, limit=None):
    keys = {'election': self}
    if category:
      keys['category'] = category
    
    return models.Voter.selectAllByKeys(keys, order_by= 'voter_id', after=after, limit=limit)
  
  def get_keyshares(self):
    return models.KeyShare.selectAllByKeys({'election' : self}, order_by = 'email')
    
  def get_keyshare_by_email(self, email):
    return models.KeyShare.selectByKeys({'election' : self, 'email' : email})
    
  def get_cast_votes(self, after=None, limit=None):
    return [voter.get_vote() for voter in self.get_voters(after=after, limit = limit) if voter.cast_id != None]

  def get_voters_hash(self):
    voters = self.get_voters()
    voters_json = utils.to_json([v.toJSONDict() for v in voters])
    logging.info("json for voters is: " + voters_json)
    return utils.hash_b64(voters_json)

  def freeze(self):
    self.frozen_at = datetime.datetime.utcnow()
    self.update()

  def is_frozen(self):
    return self.frozen_at != None

  def set_result(self, tally_d, proof_d):
    self.result_json = utils.to_json(tally_d)
    self.decryption_proof = utils.to_json(proof_d)

  def get_result(self):
    return utils.from_json(self.result_json or "null")
    
  def get_result_proof(self):
    return utils.from_json(self.decryption_proof or "null")
  
  def set_running_tally(self, running_tally):
    self.running_tally = utils.to_json(running_tally.toJSONDict())
    
  def get_running_tally(self):
    if not self.running_tally: return None
    return electionalgs.Tally.fromJSONDict(utils.from_json(self.running_tally), self.toElection())

  def set_encrypted_tally(self, tally):
    self.encrypted_tally = utils.to_json(tally.toJSONDict())
    
  def get_encrypted_tally(self):
    if not self.encrypted_tally: return None
    return electionalgs.Tally.fromJSONDict(utils.from_json(self.encrypted_tally), self.toElection())
        
  def get_first_uncounted_voter(self):
    """
    Return the voter that hasn't been counted yet, in order of cast_id
    """
    query = models.Voter.all().filter('election = ', self)
    query.filter('tallied_at = ', None).filter('cast_id > ', None)
    query.order('cast_id')
    
    return query.get()
    
  def reset_running_tally(self):
    self.running_tally = None
    self.encrypted_tally = None
    self.result_json = None
    self.save()
    
    for v in self.get_voters():
      v.tallied_at = None
      v.save()    
    
  def tally_chunk(self):
    """
    Do one chunk of the tally
    """

    # are we done?
    if self.encrypted_tally != None:
      return None
      
    running_tally = self.get_running_tally()
    first_uncounted_voter = self.get_first_uncounted_voter()

    # no further uncounted vote
    if first_uncounted_voter == None:
      self.set_encrypted_tally(running_tally)
      
      # decrypt
      self.decrypt(ElectionExponentAccessor(self))
      return None

    first_uncounted_vote = first_uncounted_voter.get_vote()

    # no running tally, set it up
    election_obj = self.toElection()
    if running_tally == None:
      running_tally = election_obj.init_tally()

    # tally the vote (includes verification)
    first_uncounted_vote.pk = election_obj.pk
    running_tally.add_vote(first_uncounted_vote)
    
    self.set_running_tally(running_tally)
    self.save()
    
    # mark vote as tallied
    first_uncounted_voter.tallied_at = datetime.datetime.utcnow()
    first_uncounted_voter.save()
    
    return running_tally

  def tally_and_decrypt(self):
    """
    Tally the decrypted votes
    """
    # load all the votes
    # FIXME: let's page this, maybe 100 at a time
    votes = self.get_cast_votes()

    election_obj = self.toElection()

    # tally the votes
    tally = election_obj.init_tally()
    for vote in votes:
      tally.add_vote(vote)
          
    self.set_encrypted_tally(tally)
    self.decrypt()

  def decrypt(self, discrete_logs = None):
    # decrypt
    tally = self.get_encrypted_tally()
    sk =  self.get_sk()
    result, proof = tally.decrypt_and_prove(sk, discrete_logs)
    self.set_result(result, proof)
    self.save()
    
  @classmethod
  def getByAdmin(cls, user, include_archived = False):
    query = cls.all().filter('admin = ', user)
    if not include_archived:
      query.filter('archived_at = ', None)
    return [r for r in query]
    
class ElectionExponentBase(DBObject):
  """
  A set of g^i for i <= num_voters, so we can do decryption easily.
  """
  
  @classmethod
  def get_max_by_election(cls, election):
    all_exps = cls.selectAllByKeys(keys={'election' : election}, order_by='-exponent', offset=None, limit=1)
    if len(all_exps) == 0:
      return None
    else:
      return all_exps[0]
      
  @classmethod
  def add_exp_to_election(cls, election):
    the_max = cls.get_max_by_election(election)
    
    pk = election.get_pk()
    if the_max == None:
      exp = 1
      value = pk.g
    else:
      exp = the_max.exponent + 1
      value = (int(the_max.value) * pk.g) % pk.p
      
    new_exp = models.ElectionExponent()
    new_exp.exponent = exp
    new_exp.value = str(value)
    new_exp.election = election
    new_exp.save()
    
  @classmethod
  def get_exp(cls, election, value):
    logging.info("looking for %s" % str(value))
    if int(value) == 1:
      return 0
      
    return cls.selectByKeys({'value': str(value), 'election' : election}).exponent
    
class ElectionExponentAccessor(object):
  """
  A class to faciliate access to election exponent
  
  everything is an int, no strings here, and ints are returned
  """
  def __init__(self, election):
    self.election = election
    
  def __getitem__(self, value):
    return int(models.ElectionExponent.get_exp(self.election, str(value)))
    
class VoterBase(DBObject):  
  JSON_FIELDS = ['voter_id','name', 'email','category']
  
  @classmethod
  def selectByEmailOrOpenID(cls, election, email, openid_url):
    email_voter = openid_voter = None
    
    if email:
      email_voter = cls.selectByKeys({'election': election, 'email': email})
    
    if openid_url:
      openid_voter = cls.selectByKeys({'election': election, 'openid_url': openid_url})
      
    # two voters, not the same?
    if email_voter and openid_voter and email_voter.voter_id != openid_voter.voter_id:
      raise Exception("problem matching openid and email")
            
    return email_voter or openid_voter
    
  def save(self):
    if not self.is_saved():
      # add an election exponent
      models.ElectionExponent.add_exp_to_election(self.election)
    
    super(VoterBase, self).save()
      
  def generate_password(self):
    self.password = utils.random_string(10)

  def set_encrypted_vote(self, votes_json_string):
    self.vote = votes_json_string
    self.vote_hash = self.compute_vote_hash()
    self.cast_id = str(datetime.datetime.utcnow()) + str(self.voter_id)
    self.save()

  def get_vote_hash(self):
    return self.vote_hash
    
  def compute_vote_hash(self):
    vote_hash = utils.hash_b64(self.vote)
    return vote_hash
  
  def get_vote(self):
    return electionalgs.EncryptedVote.fromJSONDict(utils.from_json(self.vote or "null"))
    
  def toJSONDict(self, with_vote = False):
    json_dict = super(VoterBase, self).toJSONDict()
    if not self.email and self.openid_url:
      json_dict['openid'] = self.openid_url
    if with_vote:
      json_dict['vote'] = self.get_vote().toJSONDict()
    if not json_dict['category'] or json_dict['category'] == "":
      del json_dict['category']
    return json_dict

##
## Machine API
##

class APIClient(DBObject):
  @classmethod
  def get_by_consumer_key(cls, consumer_key):
    if not consumer_key: return None
    return cls.selectByKey('consumer_key', consumer_key)


##
## Distributed Decryption
##

class KeyShareBase(DBObject):
  JSON_FIELDS = ['email','pk','pok', 'decryption_factor', 'decryption_proof']
  
  def get_pk(self):
    if not self.pk_json: return None
    return algs.EGPublicKey.fromJSONDict(utils.from_json(self.pk_json))

  def get_pok(self):
    if not self.pok_json: return None
    return utils.from_json(self.pok_json)

  def generate_password(self):
    self.password = utils.random_string(16)
  
  def toJSONDict(self):
    self.pk = self.get_pk()
    self.pok = self.get_pok()
      
    return DBObject.toJSONDict(self)
