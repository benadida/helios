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

import csv

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
    user, api_client, election = ElectionController.check(self.parent, allow_frozen = (self.parent.openreg_enabled and not self.parent.result_json))

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
    election_obj = election.toElection()

    # if election has results already
    if election.result_json:
      raise cherrypy.HTTPError(500, "Tally Already Computed")
    
    # password check
    if not voter.password == password:
      raise cherrypy.HTTPError(403, "Bad Password")

    # set in DB
    voter.set_encrypted_vote(encrypted_vote)
    
    # send a confirmation email
    mail_body = """
Dear %s,

Your vote in election "%s" was recorded.

For your verification, we include below the fingerprint of your encrypted vote:
%s

And, as a reminder, the fingerprint of the election itself is:
%s

--
The Helios Voting System
""" % (voter.name, election_obj.name, voter.get_vote_hash(), election_obj.hash)

    mail.simple_send([voter.name],[voter.email], "Helios", "ben@adida.net", "your vote was recorded", mail_body)

    return SUCCESS

class TrusteeController(REST.Resource):
  """
  A controller for voters within elections.
  """
      
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'trustee/'

  # REST stuff
  def REST_instantiate(self, trustee_email):
    return self.parent.get_keyshare_by_email(trustee_email)
    
  def REST_create(self, voter_id):
    raise NotImplemented
  ########
  
  @web
  def home(self, keyshare):
    eg_params_json = utils.to_json(ELGAMAL_PARAMS.toJSONDict())
    election = self.parent
    return self.render("home")
    
  @web
  def upload_pk(self, keyshare, password, pk, pok):
    if keyshare.password != password:
      return "failure: bad password"
      
    if self.parent.is_frozen():
      return "failure: election not frozen"
      
    self.parent.public_key_json = None
    self.parent.save()
    
    keyshare.pk_json = pk
    keyshare.pok_json = pok
    keyshare.save()
    return "success"
    
  @web
  def tally(self, keyshare):
    election = self.parent
    election_pk = election.get_pk()
    election_pk_json = utils.to_json(election_pk.toJSONDict())
    return self.render("tally")
    
  @web
  @json
  def list(self, **kw):
    """
    Output a JSON list of trustees for a given election.
    """
    election = self.parent

    keyshares = election.get_keyshares()
    return [k.toJSONDict() for k in keyshares]

  @web
  def upload_decryption_factor(self, keyshare, password, decryption_factors, decryption_proofs):
    if keyshare.password != password:
      return "failure: password doesn't match"
      
    if not self.parent.is_frozen():
      return "failure: election not frozen"
      
    keyshare.decryption_factors_json = decryption_factors
    keyshare.decryption_proofs_json = decryption_proofs
    keyshare.save()
    return "success"

  
class ElectionController(REST.Resource):
  """
  A Controller for elections.
  """
  REST_children = {'voters' : VoterController(), 'trustees' : TrusteeController()}
  
  TEMPLATES_DIR = basic.HeliosController.TEMPLATES_DIR + 'election/'
  
  @classmethod
  def check(cls, election, allow_frozen=False, require_frozen=False):
    """
    An internal check that the user is allowed to administer this given election.
    Optional parameters check the status of the election.
    """
    user = Controller.user()
    api_client = do.APIClient.get_by_consumer_key(Controller.api_client())
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
    return self.render('new')

  @web
  @session.login_protect
  def new_2(self, name, election_type):
    """
    Enter additional information about the election type.
    """
    user = Controller.user()
    
    eg_params_json = utils.to_json(ELGAMAL_PARAMS.toJSONDict())
    return self.render('new_2')
    
  @web
  @session.login_protect
  def new_3(self, name, trustee = None, public_key=None, private_key=None, voting_starts_at=None, voting_ends_at=None, **kw):
    """
    Create the new election.
    
    trustees is a JSON list
    """
    
    # we need a list of admins, or at least a public key
    if not trustee and not public_key:
      self.error('Need a list of trustees or a public key')
    
    election = do.Election()

    # hard-wire the type for now, we only have one type of election
    election.election_type = 'homomorphic'
    
    # basic election parameters
    election.name = name
    election.admin, election.api_client = self.user(), do.APIClient.get_by_consumer_key(Controller.api_client())
    election.voting_starts_at = utils.string_to_datetime(voting_starts_at)
    election.voting_ends_at = utils.string_to_datetime(voting_ends_at)

    # serialize the public key to JSON and store it if it was sent
    if public_key and public_key != "":
      pk = algs.EGPublicKey.from_dict(utils.from_json(public_key))
      election.public_key_json = utils.to_json(pk.to_dict())
    
    # the private key can be stored by the server
    if private_key and private_key != "":
      sk = algs.EGSecretKey.from_dict(utils.from_json(private_key))
      election.private_key_json = utils.to_json(sk.to_dict())
    
    ## FIXME: transaction!
    
    election.save()

    # go through the trustees
    if trustee:
      for t in trustee:
        if t.strip() == "":
          continue
        # create the keyshare
        keyshare = do.KeyShare()
        keyshare.parent = election
        keyshare.election = election
        keyshare.email = t
        keyshare.generate_password()
        keyshare.save()
        
      # send out the email
      self.email_trustees_2(election, 'You have been designated as a trustee of the Helios Election "%s".' % election.name)
    
    # user or api_client?
    if election.admin:
      raise cherrypy.HTTPRedirect("./%s/view" % str(election.election_id))
    else:
      return str(election.election_id)

  ##
  ## MANAGE key shares
  ##
  @web
  @session.login_protect
  def keyshares_manage(self, election):
    keyshares = election.get_keyshares()
    return self.render("keyshares_manage")

  @web
  @session.login_protect
  def keyshares_tally_manage(self, election):
    election_pk = election.get_pk()
    election_pk_json = utils.to_json(election_pk.toJSONDict())
    keyshares = election.get_keyshares()
    return self.render("keyshares_tally_manage")
    
  @web
  @session.login_protect
  def set_pk(self, election, pk_json):
    if election.get_pk():
      return "failure: PK exists already"
    
    election.set_pk(algs.EGPublicKey.fromJSONDict(utils.from_json(pk_json)))
    election.save()
    
    return "success"

  @web
  def view(self, election):
    """
    Human interface for viewing a given election.
    """
    user = self.user()
    admin_p = user and (user == election.admin)
    election_obj = election.toElection()
    return self.render('one')
    
  @web
  @session.login_protect
  def voters_manage(self, election):
    """
    Manage voters for the given election.
    """
    # allow managing of voters no matter what, since this is where you can email them
    user, api_client, election = self.check(election, allow_frozen=True)
    voters = election.get_voters()
    voters_json = utils.to_json([v.toJSONDict() for v in voters])
    return self.render('voters')
    
  @web
  @session.login_protect
  def voters_bulk_upload(self, election, voters_csv):
    """
    Process a bulk upload form for voters
    """
    user, api_client, election = self.check(election, allow_frozen = (election.openreg_enabled and not election.result_json))
    
    voters_csv_lines = voters_csv.split("\n")
    reader = csv.reader(voters_csv_lines)
    
    for voter in reader:
      
      if len(voter) < 2:
        continue
        
      # process the CSV and add
      v = do.Voter()
      v.election = election
      v.email = voter[1]
      v.name = voter[0]
      if len(voter) > 2:
        v.category = voter[2]
      v.generate_password()
      v.insert()
      
    return self.redirect("./voters_manage")
    
    
  @web
  def open_submit(self, election, encrypted_vote, email=None, openid_url=None, name=None, category=None):
    """
    Submitting a vote in an open election
    """
    if not election.openreg_enabled:
      self.error("Election not open")
    
    api_client = do.APIClient.get_by_consumer_key(Controller.api_client())
    if not api_client or election.api_client.api_client_id != api_client.api_client_id:
      logging.info(api_client)
      self.error("Bad Authentication")
    
    # API client is authenticated to manage this election
    
    # see if there is already a voter for this email and/or openid_url
    voter= do.Voter.selectByEmailOrOpenID(election, email, openid_url)
    
    if not voter:
      voter = do.Voter()
      voter.election = election
      voter.insert()

    # set parameters that may be updates to the existing voter
    voter.email = email
    voter.openid_url = openid_url
    voter.name = name
    voter.category = category
    voter.save()    
    
    # set the encrypted vote
    voter.set_encrypted_vote(encrypted_vote)
      
    return voter.voter_id    

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
    user, api_client, election = self.check(election, allow_frozen=True)
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
  def save_questions(self, election, questions_json):
    """
    Save the election questions.
    """
    user, api_client, election = self.check(election)

    election.save_questions(utils.from_json(questions_json))

    # always a machine API
    return "SUCCESS"

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
  def bboard(self, election, voter_email=None, voter_openid=None, after=None, offset=0, limit=20):
    """
    Display a list of encrypted votes
    """
    offset = int(offset)
    limit = int(limit)
    if not election.is_frozen():
      self.redirect("./view")
      
    # if there's a specific voter
    if voter_email or voter_openid:
      voters = [do.Voter.selectByEmailOrOpenID(election, email=voter_email, openid_url=voter_openid)]
    else:
      # load a bunch of voters
      voters = election.get_voters(after=after, limit=limit+1)
      
    more_p = len(voters) > limit
    if more_p:
      voters = voters[0:limit]
      next_after = voters[limit-1].voter_id
      next_offset = offset + limit

    return self.render('bboard')

  @web
  @session.login_protect
  def voters_delete(self, election, voter_ids):
    """
    Deleting voters.
    """
    # allow frozen only if it's open registration
    user, api_client, election = self.check(election, allow_frozen=election.openreg_enabled)
    
    voter_id_list = voter_ids.split(",")
    voters = [do.Voter.selectById(voter_id) for voter_id in voter_id_list]
    for voter in voters:
      if election.election_id != voter.election.election_id:
        self.error('bad voter')

    for voter in voters:
      voter.delete()
      
    return "success"
    
  @web
  @session.login_protect
  def voters_email(self, election_id, voter_ids=None):
    """
    Form for emailing voters.
    if voter_id is provided this emails a single voter
    """
    user, api_client, election = self.check(election_id, True, True)
    
    if voter_ids:
      voter_id_list = voter_ids.split(",")
      voters = [do.Voter.selectById(voter_id) for voter_id in voter_id_list]
      for voter in voters:
        if election.election_id != voter.election.election_id:
          self.error('bad voter')
    else:
      voters = None

    return self.render('voters_email')

  @web
  @session.login_protect
  def voters_email_2(self, election, introductory_message, voter_ids=None, after=None, limit=None):
    """
    Send email to voters of an election.
    """
    user, api_client, election = self.check(election, True, True)

    if after:
      after = str(after)
    if limit:
      limit = int(limit)
    
    if voter_ids:
      raw_voter_id_list = voter_ids.split(",")

      voter_id_list = []
      
      if after:
        # adjust the list given the value of "after"
        copy_p = False
      else:
        copy_p = True

      # mimicking after and limit
      for v_id in raw_voter_id_list:
        if copy_p:
          voter_id_list.append(v_id)
        
        if (not copy_p) and (v_id == after):
          copy_p = True
          
        if len(voter_id_list) >= limit:
          break
      
      voters = [do.Voter.selectById(voter_id) for voter_id in voter_id_list]
      for voter in voters:
        if election.election_id != voter.election.election_id:
          self.error('bad voter')
    else: 
      voters = election.get_voters(after=after, limit=limit)

    last_id = None
    
    # send as the owner of the election
    if user:
      sender_email = user.email_address
    else:
      sender_email = "ben@adida.net"

    for voter in voters:
      logging.info("sending email to %s" % voter.email)
      message_header = u"""
Dear %s,

""" % voter.name

      message_footer = u"""

Election URL: %s
Direct Voting URL: %s
Election Fingerprint: %s

Your email address: %s
Your password: %s

--
%s
via the Helios Voting System
www.heliosvoting.org
""" % ((config.webroot + '/elections/%s/view')%election.election_id, (config.webroot + '/elections/%s/vote')%election.election_id, election.toElection().get_hash(), voter.email, voter.password, sender_email)

      message = message_header
      logging.info(introductory_message)
      message += unicode(introductory_message)
      message += message_footer

      mail.simple_send([voter.name], [voter.email], "Helios", sender_email,"Voting in Election %s" % election.name, message)
      
      last_id = voter.voter_id
      
    # did we get less than the limit? if so, done
    if limit and len(voters) < limit:
      last_id = None

    # hack for now, no more batching
    return last_id or "DONE"
  
  @web
  @session.login_protect
  def email_trustees(self, election):
    keyshares = election.get_keyshares()
    return self.render('email_trustees')
    
  @web
  @session.login_protect
  def email_trustees_2(self, election, body):
    user, api_client, election = self.check(election, True)

    # the message to email
    message = """
%s

Your Trustee homepage for election "%s" is:
%s

Your password is:
%s

--
The Helios Voting System
"""

    subject = "Trustee Information for %s" % election.name

    trustees = election.get_keyshares()
    for trustee in trustees:
      full_body = message % (body, election.name, config.webroot + ('/elections/%s/trustees/%s/home' % (election.election_id, utils.urlencode(trustee.email))), trustee.password)

      # send out the emails for the shares
      mail.simple_send([trustee.email],[trustee.email],"Helios","ben@adida.net", subject, full_body)
    
    return "DONE"
    
  @web
  @session.login_protect
  def compute_tally(self, election):
    """
    Compute the election encrypted tally.
    """
    user, api_client, election = self.check(election, True, True)

    election.tally_and_decrypt()
    
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