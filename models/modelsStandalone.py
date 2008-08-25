"""
Data Objects for Helios GAE.

FIXME: refactor to be not GAE-specific, leave that to DBObject.py

Ben Adida
(ben@adida.net)
"""

from base.DBObject import DBObject
import modelsbase as mbase
from base import utils, DB

import simplejson, datetime, logging

from crypto import algs


class Election(mbase.ElectionBase):
  TABLE_NAME = 'elections'
  PRIMARY_KEY = 'election_id'
  SEQ_NAME = 'election_id_seq'
  FIELDS = ['election_id','admin_user_id','election_type','name','election_hash','questions_json','public_key_json','private_key_json',
            'election_frozen_at','voting_starts_at','voting_ends_at','openreg_enabled','encrypted_tally','running_tally','decryption_proof',
            'result_json', 'archived_at']
  
  # when JSON'ified
  JSON_FIELDS = mbase.ElectionBase.JSON_FIELDS
    
class Voter(mbase.VoterBase):
  
  JSON_FIELDS = mbase.VoterBase.JSON_FIELDS


