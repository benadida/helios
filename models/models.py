"""
Data Objects for Helios GAE.

FIXME: refactor to be not GAE-specific, leave that to DBObject.py

Ben Adida
(ben@adida.net)
"""

from base import utils
from base.DBObject import DBObject
import simplejson, datetime, logging

from crypto import algs

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp


class Election(DBObject):
  admin = db.UserProperty()
  name = db.StringProperty(multiline=False)
  public_key_json = db.TextProperty()
  private_key_json = db.TextProperty()
  questions_json = db.TextProperty()

  # dates at which things happen for the election
  frozen_at = db.DateTimeProperty(auto_now_add=False)
  voting_starts_at = db.DateTimeProperty(auto_now_add=False)
  voting_ends_at = db.DateTimeProperty(auto_now_add=False)

  # encrypted tally, each a JSON string
  # used only for homomorphic tallies
  encrypted_tally = db.TextProperty()

  # results of the election
  result_json = db.TextProperty()

  # decryption proof, a JSON object
  decryption_proof = db.TextProperty()

  # type of election (homomorphic, mixnet, possibly with more detail)
  election_type = db.StringProperty(multiline=False)

  # when JSON'ified
  JSON_FIELDS = ['name', 'pk', 'questions', 'voters_hash', 'voting_starts_at', 'voting_ends_at']
  
  election_id = property(DBObject.get_id)
  
  def toJSONDict(self):
    self.pk = self.get_pk()
    self.questions = self.get_questions()
    self.voters_hash = self.get_voters_hash()
    return DBObject.toJSONDict(self)

  def save_dict(self, d):
    self.questions_json = simplejson.dumps(d['questions'])
    self.update()

  def get_hash(self):
    str_val = simplejson.dumps(self.toJSONDict(), sort_keys=True)
    return utils.hash_b64(str_val)

  def save_questions(self, questions):
    self.questions_json = simplejson.dumps(questions)
    self.update()
    
  def set_pk(self, pk):
    self.public_key_json = simplejson.dumps(pk.to_dict())

  def get_pk(self):
    pk_json = self.public_key_json or 'null'
    return algs.EGPublicKey.from_dict(simplejson.loads(pk_json))

  def set_sk(self, sk):
    self.private_key_json = simplejson.dumps(sk.to_dict())

  def get_sk(self):
    sk_json = self.private_key_json or 'null'
    return algs.EGSecretKey.from_dict(simplejson.loads(sk_json))

  def get_questions(self):
    questions_json = self.questions_json or '[]'
    return simplejson.loads(questions_json)

  def get_voters(self):
    return Voter.selectAllByKeys({'election': self.key()})

  def get_voters_hash(self):
    voters = self.get_voters()
    voters_json = simplejson.dumps([v.toJSONDict() for v in voters])
    return utils.hash_b64(voters_json)

  def get_votes(self, question_num):
    return Voter.selectAllWithVote(election = self, question_num = question_num)

  def freeze(self):
    self.frozen_at = datetime.datetime.utcnow()
    self.update()

  def is_frozen(self):
    return self.frozen_at != None

  def set_permutations(self, perms):
    self.permutations_json = simplejson.dumps([p.to_dict() for p in perms])

  def get_permutations(self):
    return [mixnet.Permutation.from_dict(p) for p in simplejson.loads(self.permutations_json or "null")]

  def set_result(self, tally_d, proof_d):
    self.result_json = simplejson.dumps(tally_d)
    self.decryption_proof = simplejson.dumps(proof_d)

  def get_result(self):
    return simplejson.loads(self.result_json or "null")
    
  def get_result_proof(self):
    return simplejson.loads(self.decryption_proof or "null")
  
  def decoded_answers(self, question, plaintext, format_answer_func = None):
    """
    get the decoded answer in array form, with integer position of candidates selected.
    If format_answer_func is provided, that function is applied to the array of answers for a single
    question as:

    format_answer_func(question, decoded_answers_for_that_question)
    """

    int_answer = plaintext.m
    
    # convert the int to a list of candidates
    answers = []

    for i in range(len(question['answers'])):
      # look at least significant bit
      if int_answer & 1 == 1:
        answers.append(i)

      int_answer = int_answer >> 1

    if format_answer_func:
      answers = format_answer_func(question, answers)
        
    return answers
    
  def pretty_answers(self, question, plaintext):
    def prettify_answer_list(question, answer_list):
      pretty_answer_list = [question['answers'][a] for a in answer_list]
      return ", ".join(pretty_answer_list)
      
    return self.decoded_answers(question, plaintext, prettify_answer_list)

  def tally(self):
    """
    Tally the decrypted votes
    """
    # load all the votes
    # FIXME: let's page this, maybe 100 at a time
    votes = [v.get_vote() for v in self.get_voters()]
    
    pk = self.get_pk()
    
    # go through all of the questions
    questions = self.get_questions()
    num_questions = len(questions)

    tally = [None for i in range(num_questions)]      

    possible_plaintexts = [algs.EGPlaintext(1, pk), algs.EGPlaintext(pk.g, pk)]
      
    for question_num in range(num_questions):
      question = questions[question_num]
      num_answers = len(question['answers'])
      
      # verify the votes for this question
      for vote_num in range(len(votes)):
        vote = votes[vote_num]
        # verify that the vote is good
        individual_proofs = vote[question_num]['individual_proofs']
        overall_proof = vote[question_num]['overall_proof']

        # correct num of proofs
        if len(individual_proofs) != num_answers:
          raise Exception('not the right number of proofs')
        
        homomorphic_sum = None
        
        # check the individual proofs for each option of that question
        for answer_num in range(num_answers):
          # check the disjunctive proof
          ciphertext = algs.EGCiphertext.from_dict(vote[question_num]['choices'][answer_num])
          ciphertext.pk = pk

          proofs = [algs.EGZKProof.from_dict(p) for p in individual_proofs[answer_num]]
          
          if not ciphertext.verify_disjunctive_encryption_proof(possible_plaintexts, proofs, algs.EG_disjunctive_challenge_generator):
            raise Exception("Vote #%s, Question #%s, Answer #%s don't work" % (vote_num, question_num, answer_num))
            
          # compute the homomorphic sum of all the answers
          if homomorphic_sum == None:
            homomorphic_sum = ciphertext
          else:
            homomorphic_sum *= ciphertext

        # check the overall proof by homomorphic combination
        if not homomorphic_sum.verify_encryption_proof(possible_plaintexts[1], algs.EGZKProof.from_dict(vote[question_num]['overall_proof'])):
          raise Exception("Overall proof for vote #%s Question #%s doesn't work" % (vote_num, question_num))
      
      question_tally = [None for i in range(num_answers)]

      # go through the options for that question
      for answer_num in range(num_answers):
        answer_tally = None
        
        # go through all votes, picking out the vote for that question and possible answer.
        for vote in votes:
          # count it
          answer_ciphertext = algs.EGCiphertext.from_dict(vote[question_num]['choices'][answer_num])
          answer_ciphertext.pk = pk
          logging.info("answer ciphertext is %s " % simplejson.dumps(answer_ciphertext.toJSONDict()))
          if answer_tally == None:
            answer_tally = answer_ciphertext
          else:
            answer_tally *= answer_ciphertext
            
        # Now we have the tally for that answer
        question_tally[answer_num] = answer_tally.toJSONDict()
        
      # Now we have the tally for that whole question
      tally[question_num] = question_tally
    
    self.encrypted_tally = simplejson.dumps(tally)
    self.save()
    
  def decrypt(self):
    # get basic data needed
    sk = self.get_sk()    
    encrypted_tally = simplejson.loads(self.encrypted_tally)

    # for all choices of all questions (double list comprehension)
    decrypted_tally = []
    decryption_proof = []
    
    for question in encrypted_tally:
      question_tally = []
      question_proof = []
      
      for choice in question:
        plaintext_and_proof = sk.prove_decryption(algs.EGCiphertext.from_dict(choice))
        question_tally.append(ElectionExponent.get_exp(self, plaintext_and_proof['plaintext']))
        question_proof.append(plaintext_and_proof['proof'])
        
      decrypted_tally.append(question_tally)
      decryption_proof.append(question_proof)
    
    self.set_result(decrypted_tally, decryption_proof)
    self.save()
    
  @classmethod
  def getByAdmin(cls, user):
    query = cls.all().filter('admin = ', user)
    return [r for r in query]
    
class ElectionExponent(DBObject):
  """
  A set of g^i for i <= num_voters, so we can do decryption easily.
  """
  election = db.ReferenceProperty(Election)
  exponent = db.IntegerProperty()
  value = db.StringProperty(multiline=False)
  
  @classmethod
  def get_max_by_election(cls, election):
    all_exps = cls.selectAllByKeys({'election' : election.key()}, '-exponent', None, 1)
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
      
    return cls.selectByKeys({'value': str(value), 'election' : election}).exponent
    
class Voter(DBObject):
  election = db.ReferenceProperty(Election)
  email = db.StringProperty(multiline=False)
  name = db.StringProperty(multiline=False)
  password = db.StringProperty(multiline=False)
  
  # each answer to a question is a JSON string
  vote = db.TextProperty()
  vote_hash = db.StringProperty()
  
  JSON_FIELDS = ['voter_id','name', 'email']
  voter_id = property(DBObject.get_id)

  def save(self):
    if not self.is_saved():
      # add an election exponent
      ElectionExponent.add_exp_to_election(self.election)
    
    super(Voter, self).save()
      
  def generate_password(self):
    self.password = utils.random_string(10)

  def set_encrypted_vote(self, votes_json_string):
    self.vote = db.Text(votes_json_string)
    self.vote_hash = self.compute_vote_hash()
    self.save()

  def get_vote_hash(self):
    return self.vote_hash
    
  def compute_vote_hash(self):
    vote_hash = utils.hash_b64(self.vote)
    return vote_hash
  
  def get_vote(self):
    return simplejson.loads(self.vote)
    
  @classmethod
  def selectAllWithVote(cls, election, question_num):
    # TODO: check that this is really what we want given that we reversed the voter/vote
    return Vote.all().filter('election = ', election).filter('question_num=', question_num)

