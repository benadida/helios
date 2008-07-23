"""
Helios Controllers for Election and Voters within them.

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template
from crypto import algs
from models import models as do

import cherrypy, simplejson, time, logging

from google.appengine.api import users

import basic

class VoterController(REST.Resource):
      
  # REST stuff
  def REST_instantiate(self, voter_id):
    return do.Voter.selectById(voter_id)
    
  def REST_create(self, voter_id):
    return do.Voter()
  ########

  @web
  @json
  def index(self, voter):
    v_dict = voter.toJSONDict()
    v_dict['vote'] = voter.get_vote()
    return v_dict
    
  @web
  @json
  def list(self):
    election = self.parent
    voters = election.get_voters()
    return [v.toJSONDict() for v in voters]

  @web
  @session.login_protect
  def delete(self, voter, email):
    user, election = ElectionController.check(self.parent)

    voter = do.Voter.selectByKeys({'election': election.key(), 'email' : email})
    if voter:
      voter.delete()
    else:
      logging.info("no voter")

    raise cherrypy.HTTPRedirect("../../voters_manage")

  @session.login_protect
  def add(self, email, name):
    user, election = ElectionController.check(self.parent)

    v = do.Voter()
    v.election = election
    v.email = email
    v.name = name
    v.generate_password()
    v.insert()

    raise cherrypy.HTTPRedirect("../voters_manage")

  @web
  def submit(self, voter, email, password, encrypted_vote):
    election = self.parent

    if not voter.password == password:
      return FAILURE

    voter.set_encrypted_vote(encrypted_vote)
    
    mail_body = """

Your vote in the election %s was recorded.

The encryption fingerpring for your vote is:

%s

The election fingerpring is:

%s

-Helios
""" % (election.name, voter.get_vote_hash(), election.get_hash())

    mail.simple_send([voter.name],[voter.email], "Helios", "system@heliosvoting.org", "your vote was recorded", mail_body)

    logging.info("MAIL SENT: %s " % mail_body)
    
    return SUCCESS

  
class ElectionController(REST.Resource):
  REST_children = {'voters' : VoterController()}
  
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'election/'
  
  @classmethod
  def check(cls, election, allow_frozen=False, require_frozen=False):
    user = session.get_session().get_user()
    if user != election.admin:
      raise cherrypy.HTTPRedirect('/')

    if election.is_frozen() and not allow_frozen:
      raise cherrypy.HTTPError(500, 'This election is frozen and cannot be modified.')

    if not election.is_frozen() and require_frozen:
      raise cherrypy.HTTPError(500, "Election must be frozen before emailing voters.")

    return user, election
    
  # REST stuff
  def REST_instantiate(self, election_id):
    return do.Election.selectById(election_id)
    
  def REST_create(self, election_id):
    return do.Election()
  ########
  
  @web
  def verifier(self):
    return self.render('verifier')
    
  @web
  def api(self):
    """
    the cross-site messaging API frame
    """
    return self.render("api")

  ######
  ######
  
  @web
  @session.login_protect
  def new(self):
    return self.render('new')

  @web
  @session.login_protect
  def new_2(self, name, voting_starts_at, voting_ends_at):
    election = do.Election()

    election.name = name
    election.admin = self.user()
    
    election.voting_starts_at = utils.string_to_datetime(voting_starts_at)
    election.voting_ends_at = utils.string_to_datetime(voting_ends_at)

    # generate a keypair for this election
    keypair = ELGAMAL_PARAMS.generate_keypair()

    election.public_key_json = simplejson.dumps(keypair.pk.to_dict())
    election.private_key_json = simplejson.dumps(keypair.sk.to_dict())
    
    election.save()
    
    raise cherrypy.HTTPRedirect("./%s/view" % str(election.key()))

  @web
  def view(self, election):
    user = self.user()
    admin_p = user and (user == election.admin)
    return self.render('one')
    
  @web
  @session.login_protect
  def voters_manage(self, election):
    user, election = self.check(election)
    voters = election.get_voters()
    return self.render('voters')    

  @web
  @json
  def result(self, election):
    return election.get_result()

  @web
  @json
  def result_proof(self, election):
    return election.get_result_proof()
  
  @web  
  @session.login_protect
  def build(self, election):
    user, election = self.check(election)

    return self.render('build')

  @web
  @session.login_protect
  def save(self, election, election_json):
    user, election = self.check(election)

    election.save_dict(simplejson.loads(election_json))

    return self.render('build')

  @web
  def get_voter_by_email(self, election, email):
    voter = do.Voter.selectByKeys({'election': election.key(), 'email' : email})
    return str(voter.key())

  @web
  @json
  def index(self, election):
    return election.toJSONDict()

  @web
  @session.login_protect
  def freeze(self, election_id):
    user, election = self.check(election_id)

    return self.render('freeze')

  @web
  @session.login_protect
  def freeze_2(self, election):
    user, election = self.check(election)

    election.freeze()

    raise cherrypy.HTTPRedirect("/elections/%s/view" % election.key())
    
  @web
  def vote(self, election):
    if not election.is_frozen():
      raise cherrypy.HTTPRedirect("/elections/%s/view" % election_id)
    return self.render('vote')

  @web
  @session.login_protect
  def email_voters(self, election_id):
    user, election = self.check(election_id, True, True)

    return self.render('email_voters')

  @web
  @session.login_protect
  def email_voters_2(self, election, introductory_message):
    user, election = self.check(election, True, True)

    voters = election.get_voters()

    for voter in voters:
      message_header = """
Dear %s,

""" % voter.name

      message_footer = """

Voting URL: %s

Election Fingerprint: %s
Your email address: %s
Your password: %s

-Helios
""" % ((config.webroot + '/elections/%s/vote')%election.election_id, election.get_hash(), voter.email, voter.password)

      message = message_header + introductory_message + message_footer

      mail.simple_send([voter.name],[voter.email],"Helios","system@heliosvoting.org","An Invitation to Vote in %s" % election.name, message)

    raise cherrypy.HTTPRedirect("/elections/%s/view" % election.election_id)

  @web
  def board(self, election_id):
    election = do.Election.selectById(election_id)

    if not election.is_frozen():
      raise cherrypy.HTTPRedirect("/elections/%s" % election_id)

    # Just a screen for searching

    return self.render('board')

  @web
  def board_voter(self, election_id, voter_name):
    election = do.Election.selectById(election_id)

    if not election.is_frozen():
      raise cherrypy.HTTPRedirect("/elections/%s" % election_id)

    voter_name = utils.xss_strip_all_tags(voter_name)

    questions = election.get_questions()

    voter = do.Voter.selectByKeys({'election' : election, 'name' : voter_name})
    encrypted_vote = voter.get_vote()

    return self.render('board_voter')
  
  @web
  def votes(self, election_id, question_num):
    election = do.Election.selectById(election_id)

    voters =  election.get_votes(question_num)
    return simplejson.dumps([v.toJSONDict() for v in voters])

  @web
  @session.login_protect
  def compute_tally(self, election):
    user, election = self.check(election, True, True)

    election.tally()
    
    raise cherrypy.HTTPRedirect('/elections/%s/view' % election.key())
    
  @web
  @session.login_protect
  def decrypt_and_prove(self, election):
    user, election = self.check(election, True, True)

    election.decrypt()

    raise cherrypy.HTTPRedirect('/elections/%s/view' % election.key())