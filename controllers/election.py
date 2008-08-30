"""
Helios Controllers for Election and Voters within them.

Ben Adida (ben@adida.net)
"""

from base import *
from base import REST, session, Controller, template, mail, utils
from crypto import algs
import models as do

import cherrypy, time, logging

import datetime

try:
  from django.utils import simplejson
except:
  import simplejson

try:
  from google.appengine.api import users
except:
  pass

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
  def index(self, voter, **kw):
    """
    View a single voter's info as JSON.
    """
    return voter.toJSONDict(with_vote=True)
    
  @web
  @json
  def list(self, with_vote=False, category=None, after=None, limit=None, **kw):
    """
    Output a JSON list of all voters for a given election.
    """
    election = self.parent

    # normalize limit
    limit = int(limit or 500)
    if limit > 500: limit = 500
      
    voters = election.get_voters(category= category, after=after, limit= limit)
    return [v.toJSONDict(with_vote=with_vote) for v in voters]

  @web
  @session.login_protect
  def delete(self, voter, email):
    """
    Remove a given voter from an election.
    """
    user, api_client, election = ElectionController.check(self.parent)

    voter = do.Voter.selectByKeys({'election': election, 'email' : email})
    if voter:
      voter.delete()
    else:
      logging.info("no voter")

    self.redirect("../../voters_manage")

  @session.login_protect
  def add(self, email, name, category=None):
    """
    Add a new voter to an election.
    """
    user, api_client, election = ElectionController.check(self.parent)

    v = do.Voter()
    v.election = election
    v.email = email
    v.name = name
    v.category = category
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
    user = Controller.user()
    api_client = Controller.api_client()
    if user != election.admin and api_client != election.api_client:
      raise cherrypy.HTTPRedirect('/')

    if election.is_frozen() and not allow_frozen:
      raise cherrypy.HTTPError(500, 'This election is frozen and cannot be modified.')

    if not election.is_frozen() and require_frozen:
      raise cherrypy.HTTPError(500, "Election must be frozen before emailing voters.")

    return user, api_client, election
    
  # REST stuff
  def REST_instantiate(self, election_id):
    return do.Election.selectById(election_id)
    
  def REST_create(self, election_id):
    return do.Election()
  ########
  
  @web
  def test(self, **kw):
    """
    Testing OAuth
    """
    return session.get_api_client().key
    
  @web
  @json
  def params(self, **kw):
    """
    The crypto params for keys
    """
    return ELGAMAL_PARAMS.toJSONDict()
    
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
    eg_params_json = utils.to_json(ELGAMAL_PARAMS.toJSONDict())
    return self.render('new')

  @web
  @session.login_protect
  def new_2(self, name, public_key, private_key=None, voting_starts_at=None, voting_ends_at=None, **kw):
    """
    Create the new election.
    """
    election = do.Election()

    # hard-wire the type for now, we only have one type of election
    election.election_type = 'homomorphic'
    
    # basic election parameters
    election.name = name
    election.admin, election.api_client = self.user(), self.api_client()
    election.voting_starts_at = utils.string_to_datetime(voting_starts_at)
    election.voting_ends_at = utils.string_to_datetime(voting_ends_at)

    # generate a keypair for this election
    # now we generate this in JavaScript.
    # keypair = ELGAMAL_PARAMS.generate_keypair()

    # serialize the keys to JSON and store them
    pk = algs.EGPublicKey.from_dict(utils.from_json(public_key))
    election.public_key_json = utils.to_json(pk.to_dict())
    
    # the private key can be stored by the server
    if private_key and private_key != "":
      sk = algs.EGSecretKey.from_dict(utils.from_json(private_key))
      election.private_key_json = utils.to_json(sk.to_dict())
    
    election.save()
    
    # user or api_client?
    if election.admin:
      raise cherrypy.HTTPRedirect("./%s/view" % str(election.election_id))
    else:
      return str(election.election_id)

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
    user, api_client, election = self.check(election)
    voters = election.get_voters()
    return self.render('voters')

  @web
  @session.login_protect
  def set_reg(self, election, open_p=False):
    """
    Set whether this is open registration or not
    """
    user, api_client, election = self.check(election)
    open_p = bool(int(open_p))
    election.openreg_enabled = open_p
    election.save()
    
    if user:
      self.redirect("./voters_manage")
    else:
      return "SUCCESS"
    
  @web
  @session.login_protect
  def archive(self, election, archive_p=True):
    """
    archive an election
    """
    user, api_client, election = self.check(election)
    if bool(int(archive_p)):
      election.archived_at = datetime.datetime.utcnow()
    else:
      election.archived_at = None
    election.save()
    self.redirect("./view")
    
  @web
  @json
  def result(self, election, **kw):
    """
    Machine-readable (JSON) election results.
    """
    return election.get_result()

  @web
  @json
  def result_proof(self, election, **kw):
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
    user, api_client, election = self.check(election)

    return self.render('build')

  @web
  @session.login_protect
  def save(self, election, election_json):
    """
    Save the election questions.
    """
    user, api_client, election = self.check(election)

    election.save_dict(utils.from_json(election_json))

    return self.render('build')

  @web
  @json
  def get_voter_by_email(self, election, email):
    """
    Look up the voter ID by email for given election.
    """
    return do.Voter.selectByKeys({'election': election, 'email' : email}).toJSONDict()

  @web
  @json
  def get_voter_by_openid(self, election, openid_url):
    """
    Look up the voter ID by Open ID for given election.
    """
    return do.Voter.selectByKeys({'election': election, 'openid_url' : openid_url}).toJSONDict()

  @web
  @json
  def index(self, election, **kw):
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
    user, api_client, election = self.check(election_id)

    return self.render('freeze')

  @web
  @session.login_protect
  def freeze_2(self, election):
    """
    Freeze the election.
    """
    user, api_client, election = self.check(election)

    election.freeze()

    if user:
      self.redirect("/elections/%s/view" % election.election_id)
    else:
      return "SUCCESS"
    
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
    user, api_client, election = self.check(election_id, True, True)

    return self.render('email_voters')

  @web
  @session.login_protect
  def email_voters_2(self, election, introductory_message):
    """
    Send email to voters of an election.
    """
    user, api_client, election = self.check(election, True, True)

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

      mail.simple_send([voter.name],[voter.email],"Helios","ben@adida.net","An Invitation to Vote in %s" % election.name, message)

    # raise cherrypy.HTTPRedirect("/elections/%s/view" % election.election_id)
    if len(voters) == 0:
      return "DONE"
    else:
      return utils.to_json([v.toJSONDict() for v in voters])
  
  @web
  @session.login_protect
  def compute_tally(self, election):
    """
    Compute the election encrypted tally.
    """
    user, api_client, election = self.check(election, True, True)

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
  def drive_tally(self, election):
    """
    JavaScript-based driver for the entire tallying process, now done in JavaScript.
    """
    election_pk = election.get_pk()
    election_pk_json = utils.to_json(election_pk.toJSONDict())
    
    election_sk = election.get_sk()
    if election_sk:
      election_sk_json = utils.to_json(election_sk.toJSONDict())
    
    return self.render('drive_tally')
    
  @web
  @session.login_protect
  def set_tally(self, election, tally):
    """
    Set the tally and proof.
    """
    tally_obj = utils.from_json(tally)
    election.set_result(tally_obj['result'], tally_obj['result_proof'])
    election.update()
    return "success"
    
  @web
  @session.login_protect
  def compute_tally_chunk(self, election):
    """
    Compute a small chunk of the tally, because GAE is not so good with long requests
    """
    user, api_client, election = self.check(election, True, True)
    
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
    user, api_client, election = self.check(election, True, True)

    election.decrypt()

    self.redirect('/elections/%s/view' % election.election_id)