"""
Data Objects for Helios GAE.

FIXME: refactor to be not GAE-specific, leave that to DBObject.py

Ben Adida
(ben@adida.net)
"""

from base.DBObject import DBObject
import modelsbase as mbase


try:
  from django.utils import simplejson
except:
  import simplejson
  
import datetime, logging

from crypto import algs

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp

##
## Machine API
##

class APIClient(mbase.APIClient):
  consumer_key = db.StringProperty()
  consumer_secret = db.StringProperty()
  access_token = db.StringProperty()
  access_token_secret = db.StringProperty()

  api_client_id = property(DBObject.get_id)
  
class Election(mbase.ElectionBase):
  admin = db.UserProperty()
  
  # if machine-able API
  api_client = db.ReferenceProperty(APIClient)
  
  name = db.StringProperty(multiline=False)
  public_key_json = db.TextProperty()
  private_key_json = db.TextProperty()
  questions_json = db.TextProperty()
  
  # voter list fixed or open
  openreg_enabled = db.BooleanProperty(default=False)

  # dates at which things happen for the election
  frozen_at = db.DateTimeProperty(auto_now_add=False)
  voting_starts_at = db.DateTimeProperty(auto_now_add=False)
  voting_ends_at = db.DateTimeProperty(auto_now_add=False)
  archived_at = db.DateTimeProperty(auto_now_add=False, default=None)

  # encrypted tally, each a JSON string
  # used only for homomorphic tallies
  encrypted_tally = db.TextProperty()

  # results of the election
  running_tally = db.TextProperty()
  result_json = db.TextProperty()

  # decryption proof, a JSON object
  decryption_proof = db.TextProperty()

  # type of election (homomorphic, mixnet, possibly with more detail)
  election_type = db.StringProperty(multiline=False)

  # when JSON'ified
  JSON_FIELDS = ['election_id', 'name', 'pk', 'questions', 'voters_hash', 'openreg', 'voting_starts_at', 'voting_ends_at']
  
  election_id = property(DBObject.get_id)
    
class ElectionExponent(mbase.ElectionExponentBase):
  """
  A set of g^i for i <= num_voters, so we can do decryption easily.
  """
  election = db.ReferenceProperty(Election)
  exponent = db.IntegerProperty()
  value = db.StringProperty(multiline=False)

    
class Voter(mbase.VoterBase):
  election = db.ReferenceProperty(Election)
  email = db.StringProperty(multiline=False)
  openid_url = db.StringProperty(multiline = False)
  name = db.StringProperty(multiline=False)
  password = db.StringProperty(multiline=False)

  # an identifier of when the vote was cast
  # in an open registration election, the cast_id isn't set
  # until the verification happens.
  cast_id = db.StringProperty()
  tallied_at = db.DateTimeProperty(auto_now_add=False, default=None)
  
  # each answer to a question is a JSON string
  vote = db.TextProperty()
  vote_hash = db.StringProperty()
  
  # keep a copy of the voter_id that we can sort by
  voter_id = db.StringProperty()
  
  # categorize voters
  category = db.StringProperty()
  
  JSON_FIELDS = mbase.VoterBase.JSON_FIELDS
  #voter_id = property(DBObject.get_id)
  
  def save(self):
    """
    Save object.
    Save it twice if it's a new voter
    """
    # save once, get the key(), and store it in a separate field.
    if not self.is_saved():
      super(Voter, self).save()
      self.voter_id = str(self.key())

    super(Voter, self).save()
      
##
## Vote
##
class Vote(mbase.VoteBase):
  voter = db.ReferenceProperty(Voter)
  cast_at = db.DateTimeProperty(auto_now_add=True)
  vote = db.TextProperty()
  vote_hash = db.StringProperty()

  JSON_FIELDS = mbase.VoteBase.JSON_FIELDS
  
##
## Distributed Decryption
##

class KeyShare(mbase.KeyShareBase):
  election = db.ReferenceProperty(Election)
  pk_json = db.TextProperty()
  pok_json = db.TextProperty()
  email = db.StringProperty()
  password = db.StringProperty()
  
  # storing the partial decryption factors
  decryption_factors_json = db.TextProperty()
  decryption_proofs_json = db.TextProperty()  

  keyshare_id = property(DBObject.get_id)

