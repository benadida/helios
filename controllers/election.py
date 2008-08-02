"""
Helios Controllers for Election and Voters within them.

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template, mail
from crypto import algs
from models import models as do

import cherrypy, time, logging
from django.utils import simplejson

from google.appengine.api import users

import basic

# Parameters for everything
ELGAMAL_PARAMS = algs.ElGamal()
ELGAMAL_PARAMS.p = 169989719781940995935039590956086833929670733351333885026079217526937746166790934510618940073906514429409914370072173967782198129423558224854191320917329420870526887804017711055077916007496804049206725568956610515399196848621653907978580213217522397058071043503404700268425750722626265208099856407306527012763L
ELGAMAL_PARAMS.q = 84994859890970497967519795478043416964835366675666942513039608763468873083395467255309470036953257214704957185036086983891099064711779112427095660458664710435263443902008855527538958003748402024603362784478305257699598424310826953989290106608761198529035521751702350134212875361313132604049928203653263506381L
ELGAMAL_PARAMS.g = 68111451286792593845145063691659993410221812806874234365854504719057401858372594942893291581957322023471947260828209362467690671421429979048643907159864269436501403220400197614308904460547529574693875218662505553938682573554719632491024304637643868603338114042760529545510633271426088675581644231528918421974L

class VoterController(REST.Resource):
  """
  A controller for voters within elections.
  """
      
  # REST stuff
  def REST_instantiate(self, voter_id):
    return do.Voter.selectById(voter_id)
    
  def REST_create(self, voter_id):
    return do.Voter()
  ########

  @web
  @json
  def index(self, voter):
    """
    View a single voter's info as JSON.
    """
    v_dict = voter.toJSONDict()
    v_dict['vote'] = voter.get_vote()
    return v_dict
    
  @web
  @json
  def list(self):
    """
    Output a JSON list of all voters for a given election.
    """
    election = self.parent
    voters = election.get_voters()
    return [v.toJSONDict() for v in voters]

  @web
  @session.login_protect
  def delete(self, voter, email):
    """
    Remove a given voter from an election.
    """
    user, election = ElectionController.check(self.parent)

    voter = do.Voter.selectByKeys({'election': election, 'email' : email})
    if voter:
      voter.delete()
    else:
      logging.info("no voter")

    self.redirect("../../voters_manage")

  @session.login_protect
  def add(self, email, name):
    """
    Add a new voter to an election.
    """
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
    """
    A voter submits her encrypted vote.
    """
    election = self.parent

    # if election has results already
    if election.encrypted_tally:
      raise cherrypy.HTTPError(500, "Tally Already Computed")
    
    # password check
    if not voter.password == password:
      raise cherrypy.HTTPError(403, "Bad Password")

    # set in DB
    voter.set_encrypted_vote(encrypted_vote)
    
    # send a confirmation email
    mail_body = """

Your vote in the election %s was recorded.

The encryption fingerprint for your vote is:
%s

The election fingerprint is:
%s

-Helios
""" % (election.name, voter.get_vote_hash(), election.get_hash())

    mail.simple_send([voter.name],[voter.email], "Helios", "ben@adida.net", "your vote was recorded", mail_body)

    # logging.info("MAIL SENT: %s " % mail_body)
    
    return SUCCESS

  
class ElectionController(REST.Resource):
  """
  A Controller for elections.
  """
  REST_children = {'voters' : VoterController()}
  
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'election/'
  
  @classmethod
  def check(cls, election, allow_frozen=False, require_frozen=False):
    """
    An internal check that the user is allowed to administer this given election.
    Optional parameters check the status of the election.
    """
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
    """
    The JavaScript election verifier code.
    """
    return self.render('verifier')
    
  @web
  def single_ballot_verifier(self):
    """
    The JavaScript election verifier code.
    """
    return self.render('single_ballot_verifier')

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
    """
    The form for creating a new election.
    """
    return self.render('new')

  @web
  @session.login_protect
  def new_2(self, name, voting_starts_at, voting_ends_at):
    """
    Create the new election.
    """
    election = do.Election()

    # hard-wire the type for now, we only have one type of election
    election.election_type = 'homomorphic'
    
    # basic election parameters
    election.name = name
    election.admin = self.user()
    election.voting_starts_at = utils.string_to_datetime(voting_starts_at)
    election.voting_ends_at = utils.string_to_datetime(voting_ends_at)

    # generate a keypair for this election
    keypair = ELGAMAL_PARAMS.generate_keypair()

    # serialize the keys to JSON and store them
    election.public_key_json = simplejson.dumps(keypair.pk.to_dict())
    election.private_key_json = simplejson.dumps(keypair.sk.to_dict())
    
    election.save()
    
    raise cherrypy.HTTPRedirect("./%s/view" % str(election.election_id))

  @web
  def view(self, election):
    """
    Human interface for viewing a given election.
    """
    user = self.user()
    admin_p = user and (user == election.admin)
    return self.render('one')
    
  @web
  @session.login_protect
  def voters_manage(self, election):
    """
    Manage voters for the given election.
    """
    user, election = self.check(election)
    voters = election.get_voters()
    return self.render('voters')

  @web
  @json
  def result(self, election):
    """
    Machine-readable (JSON) election results.
    """
    return election.get_result()

  @web
  @json
  def result_proof(self, election):
    """
    Machine-readable (JSON) election result proof.
    """
    return election.get_result_proof()
  
  @web  
  @session.login_protect
  def build(self, election):
    """
    JavaScript human interface for building the election questions.
    """
    user, election = self.check(election)

    return self.render('build')

  @web
  @session.login_protect
  def save(self, election, election_json):
    """
    Save the election questions.
    """
    user, election = self.check(election)

    election.save_dict(simplejson.loads(election_json))

    return self.render('build')

  @web
  def get_voter_by_email(self, election, email):
    """
    Look up the voter ID by email for given election.
    """
    voter = do.Voter.selectByKeys({'election': election, 'email' : email})
    self.redirect("voters/%s" % voter.voter_id)

  @web
  @json
  def index(self, election):
    """
    Machine-readable (JSON) election information.
    """
    return election.toJSONDict()

  @web
  @session.login_protect
  def freeze(self, election_id):
    """
    Form for freezing the election: no more changes to voter list or questions.
    Ready for voting!
    """
    user, election = self.check(election_id)

    return self.render('freeze')

  @web
  @session.login_protect
  def freeze_2(self, election):
    """
    Freeze the election.
    """
    user, election = self.check(election)

    election.freeze()

    self.redirect("/elections/%s/view" % election.election_id)
    
  @web
  def vote(self, election):
    """
    JavaScript human UI for preparing a ballot.
    """
    if not election.is_frozen():
      self.redirect("./view")
    return self.render('vote')
    
  @web
  def bboard(self, election):
    """
    Display a list of encrypted votes
    """
    if not election.is_frozen():
      self.redirect("./view")
      
    # load all voters
    voters = election.get_voters()
    
    return self.render('bboard')

  @web
  @session.login_protect
  def email_voters(self, election_id):
    """
    Form for emailing voters.
    """
    user, election = self.check(election_id, True, True)

    return self.render('email_voters')

  @web
  @session.login_protect
  def email_voters_2(self, election, introductory_message, offset="0", limit="10"):
    """
    Send email to voters of an election.
    """
    user, election = self.check(election, True, True)

    voters = election.get_voters(offset = int(offset), limit = int(limit))

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

      mail.simple_send([voter.name],[voter.email],"Helios","ben@adida.net","An Invitation to Vote in %s" % election.name, message)

    # raise cherrypy.HTTPRedirect("/elections/%s/view" % election.election_id)
    if len(voters) == 0:
      return "DONE"
    else:
      return simplejson.dumps([v.toJSONDict() for v in voters])
  
  @web
  @session.login_protect
  def compute_tally(self, election):
    """
    Compute the election encrypted tally.
    """
    user, election = self.check(election, True, True)

    election.tally()
    
    self.redirect('/elections/%s/view' % election.election_id)
    
  @web
  @session.login_protect
  def drive_tally_chunk(self, election):
    """
    JavaScript-based driver for tallying by chunks
    """
    return self.render('drive_tally_chunk')

  @web
  @session.login_protect
  def compute_tally_chunk(self, election):
    """
    Compute a small chunk of the tally, because GAE is not so good with long requests
    """
    user, election = self.check(election, True, True)
    
    if election.tally_chunk():
      return "CONTINUE"
    else:
      return "DONE"
    
  @web
  @session.login_protect
  def decrypt_and_prove(self, election):
    """
    Decrypt and prove the tally.
    """
    user, election = self.check(election, True, True)

    election.decrypt()

    self.redirect('/elections/%s/view' % election.election_id)