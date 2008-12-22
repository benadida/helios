"""
Helios Models, now for Django

Ben Adida (ben@adida.net)
2008-12-19
"""

from django.db import models
from django.utils import simplejson
import datetime, logging
import utils

from django.contrib.auth import models as auth_models

from crypto import algs, electionalgs
from json import JSONField, JSONObject, dumps, loads

class Election(models.Model, JSONObject):
  # when JSON'ified
  JSON_FIELDS = ['election_id', 'name', 'pk', 'questions', 'voters_hash', 'openreg', 'voting_starts_at', 'voting_ends_at']
  
  election_id = models.AutoField(primary_key=True)
  
  # we'll use django users from now
  admin = models.ForeignKey(auth_models.User)
  
  # if machine-able API
  api_client = models.ForeignKey('APIClient', null=True)
  
  name = models.CharField(max_length=500)
  public_key = JSONField(null=True)
  private_key = JSONField(null=True)
  questions = JSONField(null=True)
  
  # voter list fixed or open
  openreg_enabled = models.BooleanField(default=False)

  # dates at which things happen for the election
  frozen_at = models.DateTimeField(auto_now_add=False, null=True)
  voting_starts_at = models.DateTimeField(auto_now_add=False, null=True)
  voting_ends_at = models.DateTimeField(auto_now_add=False, null=True)
  archived_at = models.DateTimeField(auto_now_add=False, default=None, null=True)

  # encrypted tally, each a JSON string
  # used only for homomorphic tallies
  encrypted_tally = JSONField(null = True)

  # results of the election
  running_tally = JSONField(null=True)
  result_json = JSONField(null=True)

  # decryption proof, a JSON object
  decryption_proof = JSONField(null=True)

  # type of election (homomorphic, mixnet, possibly with more detail)
  election_type = models.CharField(max_length=300, default='homomorphic')

  def toJSONDict(self):
    # JSON fields, no need!
    #self.pk = self.get_pk()
    #self.questions = self.get_questions()
    
    # depending on whether the election supports open registration
    # we could have openreg in there all the time, but for backwards compatibility
    # with existing elections, let's not include it.
    if self.openreg_enabled:
      self.openreg = True
    else:
      ## FIXME: make this more efficient for large number of voters
      self.voters_hash = self.get_voters_hash()
      
    return JSONObject.toJSONDict(self)

  def toElection(self):
    """
    Transforms to a standalone election object, independent of storage
    """
    return electionalgs.Election.fromJSONDict(self.toJSONDict())

  def get_voters(self, category=None, after=None, limit=None):
    keys = {'election': self}
    if category:
      keys['category'] = category
    
    keys['voter_id__gte'] = after
    query = Voter.objects.filter(*keys).order_by('voter_id')
    if limit:
      return query[:limit]
    else:
      return query
  
  def get_keyshares(self):
    return KeyShare.objects.filter(election = self).order_by('email')
    
  def get_keyshare_by_email(self, email):
    return KeyShare.objects.filter(election = self, email = email)
    
  def get_cast_votes(self, after=None, limit=None):
    return [voter.vote for voter in self.get_voters(after=after, limit = limit) if voter.cast_id != None]

  def get_voters_hash(self):
    voters = self.get_voters()
    voters_json = dumps([v.toJSONDict(with_vote=False, with_vote_hash=False) for v in voters])
    # logging.info("json for voters is: " + voters_json)
    return utils.hash_b64(voters_json)

  def freeze(self):
    self.frozen_at = datetime.datetime.utcnow()
    self.update()

  def is_frozen(self):
    return self.frozen_at != None

  def set_result(self, tally_d, proof_d):
    self.result = tally_d
    self.decryption_proof = proof_d

  def get_first_uncounted_voter(self):
    """
    Return the voter that hasn't been counted yet, in order of cast_id
    """
    query = Voter.objects.filter(election = self)
    query.filter(tallied_at = None).filter(cast_id__gte = None)
    query.order_by('cast_id')
    
    return query[0]
    
  def reset_running_tally(self):
    self.running_tally = None
    self.encrypted_tally = None
    self.result = None
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
      
    running_tally = self.running_tally
    first_uncounted_voter = self.get_first_uncounted_voter()

    # no further uncounted vote
    if first_uncounted_voter == None:
      self.encrypted_tally = running_tally
      
      # decrypt
      self.decrypt(ElectionExponentAccessor(self))
      return None

    first_uncounted_vote = first_uncounted_voter.vote
    
    # no running tally, set it up
    election_obj = self.toElection()
    if running_tally == None:
      running_tally = election_obj.init_tally()

    # tally the vote (includes verification)
    first_uncounted_vote.pk = election_obj.pk
    running_tally.add_vote(first_uncounted_vote)
    
    self.running_tally = running_tally
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
          
    self.encrypted_tally = tally
    self.decrypt()

  def decrypt(self, discrete_logs = None):
    # decrypt
    tally = self.encrypted_tally
    sk =  self.sk
    result, proof = tally.decrypt_and_prove(sk, discrete_logs)
    self.result = result
    self.decryption_proof = proof
    self.save()
    
  @classmethod
  def getByAdmin(cls, user, include_archived = False):
    query = cls.objects.filter(admin = user)
    if not include_archived:
      query.filter(archived_at = None)
    return query
    
class ElectionExponent(models.Model):
  """
  A set of g^i for i <= num_voters, so we can do decryption easily.
  """
  election = models.ForeignKey(Election)
  exponent = models.IntegerField()
  value = models.CharField(max_length=1000)
  
  @classmethod
  def get_max_by_election(cls, election):
    all_exps = cls.objects.filter(election = election).order_by('exponent desc')
    if len(all_exps) == 0:
      return None
    else:
      return all_exps[0]
      
  @classmethod
  def add_exp_to_election(cls, election):
    the_max = cls.get_max_by_election(election)
    
    pk = election.pk
    
    # no pk yet? Oh well
    ## FIXME: may want to be careful about this use case, though it should be ok
    if pk == None:
      return
      
    if the_max == None:
      exp = 1
      value = pk.g
    else:
      exp = the_max.exponent + 1
      value = (int(the_max.value) * pk.g) % pk.p
      
    new_exp = ElectionExponent()
    new_exp.exponent = exp
    new_exp.value = str(value)
    new_exp.election = election
    new_exp.save()
    
  @classmethod
  def get_exp(cls, election, value):
    logging.info("looking for %s" % str(value))
    if int(value) == 1:
      return 0
      
    return cls.objects.get(value = str(value), election = election).exponent
    
class ElectionExponentAccessor(object):
  """
  A class to faciliate access to election exponent
  
  everything is an int, no strings here, and ints are returned
  """
  def __init__(self, election):
    self.election = election
    
  def __getitem__(self, value):
    return int(ElectionExponent.get_exp(self.election, str(value)))
    
    
class Voter(models.Model):
  JSON_FIELDS = ['voter_id','name', 'email','category','vote_hash']
  
  voter_id = models.AutoField(primary_key=True)
  election = models.ForeignKey(Election)
  email = models.EmailField(null=True)
  openid_url = models.URLField(null=True)
  name = models.CharField(max_length=300,null=True)
  password = models.CharField(max_length=20, null=True)

  # an identifier of when the vote was cast
  # in an open registration election, the cast_id isn't set
  # until the verification happens.
  cast_id = models.CharField(max_length=100, null=True)
  tallied_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  
  # each answer to a question is a JSON string
  vote = JSONField(null=True)
  vote_hash = models.CharField(max_length=40, null=True)
  
  # categorize voters
  category = models.CharField(max_length=100, null=True)
  
  @classmethod
  def selectByEmailOrOpenID(cls, election, email, openid_url):
    email_voter = openid_voter = None
    
    ## FIXME
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
    # Check the proof on the vote
    pk = self.election.get_pk()
    election_obj = self.election.toElection()
    vote_dict = utils.from_json(votes_json_string)
    enc_vote = electionalgs.EncryptedVote.fromJSONDict(vote_dict, pk)
    
    # verify
    # turned off for now (Ben- 2008-11-28)
    #if not enc_vote.verify(election_obj):
    #  raise Exception("Vote does not verify")
      
    # store this current vote in the voter structure
    self.vote = votes_json_string
    self.vote_hash = self.compute_vote_hash()
    self.cast_id = str(datetime.datetime.utcnow()) + str(self.voter_id)
    
    # store the vote
    v = models.Vote()
    v.cast_at = datetime.datetime.utcnow()
    v.vote = votes_json_string
    v.vote_hash = self.vote_hash
    v.voter = self
    v.insert()
    
    self.save()

  def get_vote_hash(self):
    return self.vote_hash
    
  def compute_vote_hash(self):
    vote_hash = utils.hash_b64(self.vote)
    return vote_hash
  
  def get_vote(self):
    vote_dict = utils.from_json(self.vote or "null")

    # null vote
    if not vote_dict or vote_dict == "":
      return None

    return electionalgs.EncryptedVote.fromJSONDict(vote_dict)
    
  def toJSONDict(self, with_vote = False, with_vote_hash = True):
    json_dict = super(Voter, self).toJSONDict()
    
    if not with_vote_hash:
      del json_dict['vote_hash']

    if not self.email and self.openid_url:
      json_dict['openid'] = self.openid_url

    if with_vote:
      vote = self.get_vote()
      if vote:
        json_dict['vote'] = vote.toJSONDict()
      else:
        json_dict['vote'] = None

    if not json_dict['category'] or json_dict['category'] == "":
      del json_dict['category']

    return json_dict
    
##
## Keep track of all cast votes
##
class Vote(models.Model):
  JSON_FIELDS = ['vote_id', 'cast_at', 'vote']
  
  vote_id = models.AutoField(primary_key=True)
  voter = models.ForeignKey(Voter, related_name = 'all_votes')
  cast_at = models.DateTimeField(auto_now_add=True)
  vote = JSONField()
  vote_hash = models.CharField(max_length=100)

##
## Machine API
##

class APIClient(models.Model):
  api_client_id = models.AutoField(primary_key=True)
  consumer_key = models.CharField(max_length=100)
  consumer_secret = models.CharField(max_length=100)
  access_token = models.CharField(max_length=100)
  access_token_secret = models.CharField(max_length=100)

  @classmethod
  def get_by_consumer_key(cls, consumer_key):
    if not consumer_key: return None
    return cls.objects.get(consumer_key = consumer_key)


##
## Distributed Decryption
##

class KeyShare(models.Model):
  JSON_FIELDS = ['email','pk','pok', 'decryption_factors', 'decryption_proofs']
  
  keyshare_id = models.AutoField(primary_key = True)
  
  election = models.ForeignKey(Election)
  pk = JSONField(null=True)
  pok = JSONField(null=True)
  email = models.EmailField()
  password = models.CharField(max_length=50, null=True)
  
  # storing the partial decryption factors
  decryption_factors = JSONField(null=True)
  decryption_proofs = JSONField(null=True)  

  
  def get_pk(self):
    if not self.pk: return None
    return algs.EGPublicKey.fromJSONDict(self.pk)

  def generate_password(self):
    self.password = utils.random_string(16)