"""
Election-specific algorithms for Helios

Ben Adida
2008-08-30
"""

import algs
from base import utils

class EncryptedAnswer(object):
  """
  An encrypted answer to a single election question
  """
  def __init__(self):
    self.choices = None
    self.individual_proofs = None
    self.overall_proof = None
    self.randomness = None
    
  def verify(self, pk):
    possible_plaintexts = [algs.EGPlaintext(1, pk), algs.EGPlaintext(pk.g, pk)]
    homomorphic_sum = 0

    for choice_num in range(len(self.choices)):
      choice = self.choices[choice_num]
      choice.pk = pk
      individual_proof = self.individual_proofs[choice_num]
      
      # verify the proof on the encryption of that choice
      if not choice.verify_disjunctive_encryption_proof(possible_plaintexts, individual_proof, algs.EG_disjunctive_challenge_generator):
        return False

      # compute homomorphic sum
      homomorphic_sum = choice * homomorphic_sum
    
    # verify the sum
    return homomorphic_sum.verify_disjunctive_encryption_proof(possible_plaintexts, self.overall_proof, algs.EG_disjunctive_challenge_generator)
        
  def toJSONDict(self):
    return {
      'choices': [c.to_dict() for c in self.choices],
      'individual_proofs' : [p.to_dict() for p in self.individual_proofs],
      'overall_proof': self.overall_proof.to_dict()
    }
    
  @classmethod
  def fromJSONDict(cls, d, pk):
    ea = cls()

    ea.choices = [algs.EGCiphertext.from_dict(c, pk) for c in d['choices']]
    ea.individual_proofs = [algs.EGZKDisjunctiveProof.from_dict(p) for p in d['individual_proofs']]
    ea.overall_proof = algs.EGZKDisjunctiveProof.from_dict(d['overall_proof'])

    if d.has_key('randomness'):
      ea.randomness = [int(r) for r in d['randomness']]
      ea.answer = d['answer']
      
    return ea
  
class EncryptedVote(object):
  """
  A complete encrypted ballot
  """
  def __init__(self):
    self.encrypted_answers = None
    self.election_hash = None
    self.election_id = None
    
  def verify(self, election):
    # right number of answers
    if len(self.encrypted_answers) != len(election.questions):
      return False
    
    # check hash
    if self.election_hash != election.hash:
      return False
      
    # check ID
    if self.election_id != election.election_id:
      return False
      
    # check proofs on all of answers
    for ea in self.encrypted_answers:
      if not ea.verify(election.pk):
        return False
        
    return True
    
  def toJSONDict(self):
    return {
      'answers': [EncryptedAnswer.toJSONDict(a) for a in self.encrypted_answers],
      'election_hash': self.election_hash,
      'election_id': self.election_id
    }
    
  @classmethod
  def fromJSONDict(cls, d, pk=None):
    ev = cls()

    ev.encrypted_answers = [EncryptedAnswer.fromJSONDict(ea, pk) for ea in d['answers']]
    ev.election_hash = d['election_hash']
    ev.election_id = d['election_id']

    return ev
    
class Election(object):
  
  def __init__(self):
    self.pk = None
    self.election_id = None
    self.questions = None
    self.name = None
    self.voters_hash = None
    self.voting_starts_at = None
    self.voting_ends_at = None
    self.openreg = False
    
  def init_tally(self):
    return Tally(self)
    
  def get_hash(self):
    return utils.hash_b64(utils.to_json(self.toJSONDict()))
    
  hash = property(get_hash)

  def toJSONDict(self):
    return {
      'election_id' : self.election_id,
      'name' : self.name,
      'pk' : self.pk.toJSONDict(),
      'questions' : self.questions,
      'voters_hash' : self.voters_hash,
      'voting_starts_at' : self.voting_starts_at,
      'voting_ends_at' : self.voting_ends_at
    }
    
  @classmethod
  def fromJSONDict(cls, d):
    el = cls()
    el.election_id = d['election_id']
    el.name = d['name']
    el.voters_hash = d['voters_hash']
    el.voting_starts_at = d['voting_starts_at']
    el.voting_ends_at = d['voting_ends_at']
    el.questions = d['questions']
    el.pk = algs.EGPublicKey.fromJSONDict(d['pk'])

    return el
    
  
class Tally(object):
  """
  A running homomorphic tally
  """
  def __init__(self, election):
    self.questions = election.questions
    self.pk = election.pk
    self.election = election
    
    self.tally = [[0 for a in q['answers']] for q in self.questions]
    self.num_tallied = 0
    
    # keep track of exponential values for discrete log calculations
    self.discrete_logs = {}
    self.discrete_logs[1] = 0
    self.last_dl_result = 1
    
  def add_vote(self, encrypted_vote):
    # verify the vote
    encrypted_vote.pk = self.pk
    if not encrypted_vote.verify(self.election):
      raise Exception('Bad Vote')

    # for each question
    for question_num in range(len(self.questions)):
      question = self.questions[question_num]
      
      # for each possible answer to each question
      for answer_num in range(len(question['answers'])):
        # do the homomorphic addition into the tally
        self.tally[question_num][answer_num] = encrypted_vote.encrypted_answers[question_num].choices[answer_num] * self.tally[question_num][answer_num]
      
    # tally the vote
    self.__increment_precomp()

  def __increment_precomp(self):
    # add to the discrete log pre-computation
    self.num_tallied += 1
    new_value = (self.last_dl_result * self.pk.g) % self.pk.p
    self.discrete_logs[new_value] = self.num_tallied
    self.last_dl_result = new_value
    
  def decrypt_and_prove(self, sk, discrete_logs=None):
    """
    returns an array of tallies and a corresponding array of decryption proofs.
    """
    
    # who's keeping track of discrete logs?
    if not discrete_logs:
      discrete_logs = self.discrete_logs
      
    # for all choices of all questions (double list comprehension)
    decrypted_tally = []
    decryption_proof = []
    
    for question_num in range(len(self.questions)):
      question = self.questions[question_num]
      question_tally = []
      question_proof = []

      for answer_num in range(len(question['answers'])):
        # do decryption and proof of it
        plaintext, proof = sk.prove_decryption(self.tally[question_num][answer_num])

        # look up appropriate discrete log
        question_tally.append(discrete_logs[plaintext])
        question_proof.append(proof)
        
      decrypted_tally.append(question_tally)
      decryption_proof.append(question_proof)
    
    return decrypted_tally, decryption_proof
    
  def __repr__(self):
    return str(self.tally)

  def toJSONDict(self):
    return [[a.toJSONDict() for a in q] for q in self.tally]
    
  @classmethod
  def fromJSONDict(cls, election):
    tally = cls(election)
    tally.tally = [[EGCiphertext.fromJSONDict(a) for a in q] for q in d]
    return tally
    
