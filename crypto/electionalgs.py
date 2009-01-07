"""
Election-specific algorithms for Helios

Ben Adida
2008-08-30
"""

import algs
import logging

from helios import utils

class EncryptedAnswer(object):
  """
  An encrypted answer to a single election question
  """
  def __init__(self, choices=None, individual_proofs=None, overall_proof=None, randomness=None):
    self.choices = choices
    self.individual_proofs = individual_proofs
    self.overall_proof = overall_proof
    self.randomness = randomness
    
  @classmethod
  def generate_plaintexts(cls, pk, min=0, max=1):
    plaintexts = []
    running_product = 1
    
    # run the product up to the min
    for i in range(max+1):
      # if we're in the range, add it to the array
      if i >= min:
        plaintexts.append(algs.EGPlaintext(running_product, pk))
        
      # next value in running product
      running_product = (running_product * pk.g) % pk.p
      
    return plaintexts

    
  def verify(self, pk, min=0, max=1):
    possible_plaintexts = self.generate_plaintexts(pk)
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
    
    # determine possible plaintexts for the sum
    sum_possible_plaintexts = self.generate_plaintexts(pk, min=min, max=max)

    # verify the sum
    return homomorphic_sum.verify_disjunctive_encryption_proof(sum_possible_plaintexts, self.overall_proof, algs.EG_disjunctive_challenge_generator)
        
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

  @classmethod
  def fromElectionAndAnswer(cls, election, question_num, answer_indexes):
    """
    Given an election, a question number, and a list of answers to that question
    in the form of an array of 0-based indexes into the answer array,
    produce an EncryptedAnswer that works.
    """
    question = election.questions[question_num]
    answers = question['answers']
    pk = election.pk
    
    # initialize choices, individual proofs, randomness and overall proof
    choices = [None for a in range(len(answers))]
    individual_proofs = [None for a in range(len(answers))]
    overall_proof = None
    randomness = [None for a in range(len(answers))]
    
    # possible plaintexts [0, 1]
    plaintexts = cls.generate_plaintexts(pk)
    
    # keep track of number of options selected.
    num_selected_answers = 0;
    
    # homomorphic sum of all
    homomorphic_sum = 0
    randomness_sum = 0
    
    # go through each possible answer and encrypt either a g^0 or a g^1.
    for answer_num in range(len(answers)):
      plaintext_index = 0
      
      # assuming a list of answers
      if answer_num in answer_indexes:
        plaintext_index = 1
        num_selected_answers += 1

      # randomness and encryption
      randomness[answer_num] = algs.Utils.random_mpz_lt(pk.q)
      choices[answer_num] = pk.encrypt_with_r(plaintexts[plaintext_index], randomness[answer_num])
      
      # generate proof
      individual_proofs[answer_num] = choices[answer_num].generate_disjunctive_encryption_proof(plaintexts, plaintext_index, 
                                                randomness[answer_num], algs.EG_disjunctive_challenge_generator)
                                                
      # sum things up homomorphically
      homomorphic_sum = choices[answer_num] * homomorphic_sum
      randomness_sum = (randomness_sum + randomness[answer_num]) % pk.q

    # prove that the sum is 0 or 1 (can be "blank vote" for this answer)
    # num_selected_answers is 0 or 1, which is the index into the plaintext that is actually encoded
    min_answers = 0
    if question.has_key('min'):
      min_answers = question['min']
    max_answers = question['max']
    
    if num_selected_answers < min_answers:
      raise Exception("Need to select at least %s answer(s)" % min_answers)
    
    sum_plaintexts = cls.generate_plaintexts(pk, min=min_answers, max=max_answers)
    
    # need to subtract the min from the offset
    overall_proof = homomorphic_sum.generate_disjunctive_encryption_proof(sum_plaintexts, num_selected_answers - min_answers, randomness_sum, algs.EG_disjunctive_challenge_generator);
    
    return cls(choices, individual_proofs, overall_proof, randomness)
    
  
class EncryptedVote(object):
  """
  A complete encrypted ballot
  """
  def __init__(self, encrypted_answers = None, election_hash = None, election_id = None):
    self.encrypted_answers = encrypted_answers
    self.election_hash = election_hash
    self.election_id = election_id
    
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
    for question_num in range(len(election.questions)):
      ea = self.encrypted_answers[question_num]
      question = election.questions[question_num]
      min_answers = 0
      if question.has_key('min'):
        min_answers = question['min']
        
      if not ea.verify(election.pk, min=min_answers, max=question['max']):
        return False
        
    return True
    
  def get_hash(self):
    return utils.hash_b64(utils.to_json(self.toJSONDict()))
    
  def toJSONDict(self):
    return {
      'answers': [a.toJSONDict() for a in self.encrypted_answers],
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
    
  @classmethod
  def fromElectionAndAnswers(cls, election, answers):
    pk = election.pk

    # each answer is an index into the answer array
    encrypted_answers = [EncryptedAnswer.fromElectionAndAnswer(election, answer_num, answers[answer_num]) for answer_num in range(len(answers))]
    return cls(encrypted_answers, election.hash, election.election_id)
    
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
    self.ballot_type = False
    self.tally_type = False
    
  def init_tally(self):
    return Tally(self)
    
  def get_hash(self):
    return utils.hash_b64(utils.to_json(self.toJSONDict()))
    
  hash = property(get_hash)

  def toJSONDict(self):
    return_value = {
      'ballot_type' : self.ballot_type,
      'election_id' : self.election_id,
      'name' : self.name,
      'public_key' : self.pk.toJSONDict(),
      'questions' : self.questions,
      'tally_type' : self.tally_type,
      'voting_starts_at' : self.voting_starts_at,
      'voting_ends_at' : self.voting_ends_at
    }
    
    if self.openreg:
      return_value['openreg'] = True
    else:
      return_value['voters_hash'] = self.voters_hash
      
    return return_value
    
  @classmethod
  def fromJSONDict(cls, d):
    el = cls()
    el.election_id = d['election_id']
    el.name = d['name']
    if d.has_key('voters_hash'): el.voters_hash = d['voters_hash']
    if d.has_key('openreg'): el.openreg = d['openreg']
    el.voting_starts_at = d['voting_starts_at']
    el.voting_ends_at = d['voting_ends_at']
    el.questions = d['questions']
    el.ballot_type = d['ballot_type']
    el.tally_type = d['tally_type']
    
    if d['public_key']:
      el.pk = algs.EGPublicKey.fromJSONDict(d['public_key'])
    else:
      el.pk = None

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
    
  def add_vote_batch(self, encrypted_votes):
    """
    Add a batch of votes. Eventually, this will be optimized to do an aggregate proof verification
    rather than a whole proof verif for each vote.
    """
    for vote in encrypted_votes:
      self.add_vote(vote)
    
  def add_vote(self, encrypted_vote):
    # verify the vote
    encrypted_vote.pk = self.pk
    if not encrypted_vote.verify(self.election):
      raise Exception('Bad Vote')

    # for each question
    for question_num in range(len(self.questions)):
      question = self.questions[question_num]
      answers = question['answers']
      
      # for each possible answer to each question
      for answer_num in range(len(answers)):
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
      answers = question['answers']
      question_tally = []
      question_proof = []

      for answer_num in range(len(answers)):
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
  def fromJSONDict(cls, d, election):
    tally = cls(election)
    tally.tally = [[algs.EGCiphertext.fromJSONDict(a, election.pk) for a in q] for q in d]
    return tally
    
