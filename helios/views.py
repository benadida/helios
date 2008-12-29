"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.http import *
from security import *

from django.template import Context, Template, loader
from django.contrib.auth.decorators import login_required
from django.contrib import auth

from crypto import algs
import utils

import csv

from models import *

# Parameters for everything
ELGAMAL_PARAMS = algs.ElGamal()
ELGAMAL_PARAMS.p = 169989719781940995935039590956086833929670733351333885026079217526937746166790934510618940073906514429409914370072173967782198129423558224854191320917329420870526887804017711055077916007496804049206725568956610515399196848621653907978580213217522397058071043503404700268425750722626265208099856407306527012763L
ELGAMAL_PARAMS.q = 84994859890970497967519795478043416964835366675666942513039608763468873083395467255309470036953257214704957185036086983891099064711779112427095660458664710435263443902008855527538958003748402024603362784478305257699598424310826953989290106608761198529035521751702350134212875361313132604049928203653263506381L
ELGAMAL_PARAMS.g = 68111451286792593845145063691659993410221812806874234365854504719057401858372594942893291581957322023471947260828209362467690671421429979048643907159864269436501403220400197614308904460547529574693875218662505553938682573554719632491024304637643868603338114042760529545510633271426088675581644231528918421974L

##
## BASICS
##

SUCCESS = HttpResponse("SUCCESS")

##
## template abstraction
##
def render_template(request, template_name, vars = {}):
  t = loader.get_template(template_name + '.html')
  
  vars_with_user = vars.copy()
  vars_with_user['user'] = get_user(request)
  vars_with_user['utils'] = utils
  c = Context(vars_with_user)
  return HttpResponse(t.render(c))
  
def render_json(json_txt):
  return HttpResponse(json_txt)

# decorator
def json(func):
    """
    A decorator that serializes the output to JSON before returning to the
    web client.
    """
    def convert_to_json(self, *args, **kwargs):
      return render_json(utils.to_json(func(self, *args, **kwargs)))

    return convert_to_json

# Create your views here.
def home(request):
  return render_template(request, "index")
  
def learn(request):
  return render_template(request, "learn")
  
def faq(request):
  return render_template(request, "faq")
  
def about(request):
  return HttpResponse(request, "about")
  
##
## User
##

@login_required
def user_home(request):
  include_archived = request.GET.get('include_archived', False)
  
  user = get_user(request)
  
  if include_archived:
    elections = Election.objects.filter(admin = user)
  else:
    elections = Election.objects.filter(admin = user, archived_at = None)
    
  return render_template(request, "user_home", {'elections' : elections, 'include_archived':request.GET.get('include_archived', 0)})
  
def user_logout(request):
  auth.logout(request)
  return HttpResponseRedirect("/")
  
##
## General election features
##

@json
def election_params(request):
  return ELGAMAL_PARAMS.toJSONDict()

def election_verifier(request):
  return render_template(request, "tally_verifier")

def election_single_ballot_verifier(request):
  return render_template(request, "ballot_verifier")

def election_js_api(request):
  return render_template(request, "js_api")

def election_new(request):
  return render_template(request, "election_new")

def election_new_2(request):
  return render_template(request, "election_new_2", {'eg_params_json' : utils.to_json(ELGAMAL_PARAMS.toJSONDict()),
                                                    'name': request.GET['name'], 'election_type': request.GET['election_type']})
  
def election_new_3(request):
  """
  Create the new election.
  name, trustee = None, public_key=None, private_key=None, voting_starts_at=None, voting_ends_at=None, **kw
  
  trustees is a JSON list
  """
  
  name = request.POST['name']
  trustee = request.POST.get('trustee', None)
  public_key = request.POST.get('public_key', None)
  private_key = request.POST.get('private_key', None)
  voting_starts_at = request.POST.get('voting_starts_at', None)
  voting_ends_at = request.POST.get('voting_ends_at', None)
  
  # we need a list of admins, or at least a public key
  if not trustee and not public_key:
    raise HttpResponseServerError('Need a list of trustees or a public key')
  
  # create an election
  # FIXME: api client needs to be added here
  if public_key and public_key != "":
    pk = algs.EGPublicKey.from_dict(utils.from_json(public_key))
  else:
    pk = None
    
  if private_key and private_key != "":
    sk = algs.EGSecretKey.from_dict(utils.from_json(private_key))
  else:
    sk = None
    
  election = Election.objects.create(election_type = 'homomorphic', name = name, admin = get_user(request), api_client=None,
                      voting_starts_at = utils.string_to_datetime(voting_starts_at),
                      voting_ends_at = utils.string_to_datetime(voting_ends_at),
                      public_key = pk, private_key = sk)
  
  ## FIXME: transaction!
  
  # go through the trustees
  if trustee:
    for t in trustee:
      if t.strip() == "":
        continue
      # create the keyshare
      keyshare = KeyShare.objects.create(election = election, email = t)
      keyshare.generate_password()
      keyshare.save()
      
    # send out the email
    email_trustees_2(election, 'You have been designated as a trustee of the Helios Election "%s".' % election.name)
  
  # user or api_client?
  if election.admin:
    return HttpResponseRedirect("./%s/view" % str(election.election_id))
  else:
    return HttpResponse(str(election.election_id))

##
## Specific election features
##

@election_admin
def one_election_keyshares_manage(request, election):
  return HttpResponse("election keyshares %s" % election.election_id)

@election_admin
def one_election_keyshares_tally_manage(request, election):
  return HttpResponse("election keyshares tally %s" % election.election_id)
  
@election_view
@json
def one_election(request, election):
  return election.toElection().toJSONDict()

@election_view
def one_election_view(request, election):
  user = get_user(request)
  admin_p = user_can_admin_election(user, election)
  election_obj = election.toElection()
  return render_template(request, 'election_view', {'election' : election, 'election_obj' : election_obj, 'admin_p': admin_p})

@election_admin
def one_election_open_submit(request, election):
  return HttpResponse("election open submit %s" % election.election_id)

@election_view
@json
def one_election_result(request, election):
  return election.result

@election_view
@json
def one_election_result_proof(request, election):
  return election.decryption_proof
  

@election_view
@json
def one_election_get_voter_by_email(request, election):
  return Voter.objects.get(election = election, email = request.GET['email']).toJSONDict()

@election_view
def one_election_get_voter_by_openid(request, election):
  return HttpResponse("election get voter by openid %s" % election.election_id)

@election_view
def one_election_vote(request, election):
  """
  UI to vote in an election
  """
  return render_template(request, "vote", {'election': election})

@election_view
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  offset = int(request.GET.get('offset', 0))
  limit = int(request.GET.get('limit', 20))

  if not election.is_frozen():
    return HttpResponseRedirect("./view")
    
  # if there's a specific voter
  if request.GET.has_key('voter_email') or request.GET.has_key('voter_openid'):
    voters = [Voter.selectByEmailOrOpenID(election, email= request.GET.get('voter_email', None), openid_url= request.GET.get('voter_openid', None))]
  else:
    # load a bunch of voters
    voters = election.get_voters(after=request.GET.get('after', None), limit=limit+1)
    
  more_p = len(voters) > limit
  if more_p:
    voters = voters[0:limit]
    next_after = voters[limit-1].voter_id
    next_offset = offset + limit
  else:
    next_after = None
    next_offset = None
    
  return render_template(request, 'election_bboard', {'election': election, 'voters': voters, 'next_after': next_after,
                'next_offset': next_offset, 'voter_email': request.GET.get('voter_email', ''),
                'offset_plus_one': offset+1, 'offset_plus_limit': offset+limit})
  
@election_admin
def one_election_set_pk(request, election):
  return HttpResponse("election set pk %s" % election.election_id)

@election_admin
def one_election_voters_manage(request, election):
  voters = election.get_voters()
  voters_json = utils.to_json([v.toJSONDict() for v in voters])
  
  return render_template(request, "election_voters_manage", {'voters_json' : voters_json, 'voters': voters,'election': election})

@election_admin
def one_election_voters_bulk_upload(request, election):
  # FIXME: check if either open reg or not frozen
  
  voters_csv_lines = request.POST['voters_csv'].split("\n")
  reader = csv.reader(voters_csv_lines)
  
  for voter in reader:
    
    if len(voter) < 2:
      continue
      
    # process the CSV and add
    v = Voter.objects.create(election = election, email = voter[1], name = voter[0])
    
    if len(voter) > 2:
      v.category = voter[2]
    else:
      v.category = ''
      
    v.generate_password()
    v.save()
    
  return HttpResponseRedirect("./voters_manage")
  
@election_admin
def one_election_voters_delete(request, election):
  ## FIXME: check if election is frozen and can have voter deletion
  
  voter_id_list = request.POST['voter_ids'].split(",")
  voters = [Voter.objects.get(voter_id = voter_id) for voter_id in voter_id_list]
  for voter in voters:
    if election != voter.election:
      return HttpResponseServerError('bad voter')

  for voter in voters:
    voter.delete()
    
  return SUCCESS

@election_admin
def one_election_voters_email(request, election):
  if request.POST.has_key('voter_ids'):
    voter_id_list = request.POST['voter_ids'].split(",")
    voters = [Voter.objects.get(voter_id = voter_id) for voter_id in voter_id_list]
    for voter in voters:
      if election.election_id != voter.election_id:
        return HttpResponseServerError("Bad Voter")
  else:
    voters = None
  
  return render_template(request, 'voters_email', {'voter_ids' : request.POST['voter_ids'], 'voters': voters, 'election': election})

@election_admin
def one_election_voters_email_2(request, election):
  after = request.POST.get('after', None)
  limit = request.POST.get('limit', None)
    
  if request.POST.has_key('voter_ids'):
    raw_voter_id_list = request.POST['voter_ids'].split(",")

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
      
    voters = [Voter.objects.get(voter_id = voter_id) for voter_id in voter_id_list]
    for voter in voters:
      if election.election_id != voter.election.election_id:
        return HttpResponseServerError('bad voter')
  else: 
    voters = election.get_voters(after=after, limit=limit)

  last_id = None
    
  # send as the owner of the election
  if request.user.is_authenticated():
    sender_email = request.user.email
  else:
    sender_email = "system@heliosvoting.org"

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
""" % ((settings.SERVER_HOST + '/elections/%s/view')%election.election_id, (settings.SERVER_HOST + '/elections/%s/vote')%election.election_id, election.toElection().get_hash(), voter.email, voter.password, sender_email)

    message = message_header
    message += unicode(request.POST['introductory_message'])
    message += message_footer

    # FIXME: do actual mail sending
    # mail.simple_send([voter.name], [voter.email], "Helios", sender_email,"Voting in Election %s" % election.name, message)
    logging.error("would be sending mail right now to " + voter.email)
    
    last_id = voter.voter_id
      
    # did we get less than the limit? if so, done
    if limit and len(voters) < limit:
      last_id = None

  # hack for now, no more batching
  return HttpResponse(last_id or "DONE")

@election_admin
def one_election_set_reg(request, election):
  """
  Set whether this is open registration or not
  """
  open_p = bool(int(request.POST['open_p']))
  election.openreg_enabled = open_p
  election.save()
  
  if request.user.is_authenticated():
    return HttpResponseRedirect("./voters_manage")
  else:
    return SUCCESS

@election_admin
def one_election_archive(request, election):
  
  archive_p = request.GET.get('archive_p', True)
  
  if bool(int(archive_p)):
    election.archived_at = datetime.datetime.utcnow()
  else:
    election.archived_at = None
  election.save()

  return HttpResponseRedirect('./view')

@election_admin
def one_election_build(request, election):
  return render_template(request, 'election_build', {'election': election})

@election_admin
def one_election_save_questions(request, election):
  election.questions = utils.from_json(request.POST['questions_json']);
  election.save()

  # always a machine API
  return SUCCESS

@election_admin
def one_election_freeze(request, election):
  if request.method == "GET":
    return render_template(request, 'election_freeze', {'election': election})
  else:
    election.freeze()

    if request.user.is_authenticated():
      return HttpResponseRedirect("/elections/%s/view" % election.election_id)
    else:
      return SUCCESS    

@election_admin
def one_election_email_trustees(request, election):
  pass

@election_admin
def one_election_compute_tally(request, election):
  return HttpResponse("election compute tally %s" % election.election_id)

@election_admin
def one_election_drive_tally_chunk(request, election):
  return HttpResponse("election drive tally chunk %s" % election.election_id)

@election_admin
def one_election_drive_tally(request, election):
  """
  JavaScript-based driver for the entire tallying process, now done in JavaScript.
  """
  election_pk = election.public_key
  election_pk_json = utils.to_json(election_pk.toJSONDict())
  
  election_sk = election.private_key
  if election_sk:
    election_sk_json = utils.to_json(election_sk.toJSONDict())
  else:
    election_sk_json = None
  
  return render_template(request, 'drive_tally', {'election': election, 'election_pk_json' : election_pk_json, 'election_sk_json' : election_sk_json})

@election_admin
def one_election_set_tally(request, election):
  """
  Set the tally and proof.
  """
  tally_obj = utils.from_json(request.POST['tally'])
  election.set_result(tally_obj['result'], tally_obj['result_proof'])
  election.save()
  return SUCCESS

@election_admin
def one_election_compute_tally_chunk(request, election):
  return HttpResponse("election compute tally chunk %s" % election.election_id)

# Individual Voters
@election_view
@json
def voter_list(request, election):
  # normalize limit
  limit = int(request.GET.get('limit', 500))
  if limit > 500: limit = 500
    
  voters = election.get_voters(category= request.GET.get('category', None), after=request.GET.get('after',None), limit= limit)
  return [v.toJSONDict(with_vote=request.GET.get('with_vote')) for v in voters]
  

@election_admin
def voter_add(request, election):
  v = Voter.objects.create(election = election, email = request.POST['email'], name = request.POST['name'], 
                            category = request.POST['category'])
  v.generate_password()
  v.save()

  return HttpResponseRedirect("../voters_manage")

@election_view
@json
def one_voter(request, election, voter_id):
  """
  View a single voter's info as JSON.
  """
  voter = Voter.objects.get(voter_id = voter_id)
  return voter.toJSONDict(with_vote=True)  

@election_admin
def one_voter_delete(request, election, voter_id):
  return HttpResponse("voter delete for election %s" % election.election_id)

@election_view
def one_voter_submit(request, election, voter_id):
  election_obj = election.toElection()
  
  # this will raise an exception if the voter is bad
  voter = Voter.objects.get(voter_id = voter_id, election = election)

  # if election is not in progress
  if not election.in_progress_p():
    return HttpResponseServerError("Election is not/no longer in progress")
    
  # password check
  if voter.password != request.POST['password']:
    return HttpResponseServerError("Bad Password")

  # set in DB
  voter.set_encrypted_vote(request.POST['encrypted_vote'])
    
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

  # FIXME: send mail
  # mail.simple_send([voter.name],[voter.email], "Helios", "system@heliosvoting.org", "your vote was recorded", mail_body)
  logging.error("would send mail to confirm voter " + voter.email)

  return SUCCESS  

# Trustees
@election_view
@json
def trustees_list(request, election):
  keyshares = election.get_keyshares()
  return [k.toJSONDict() for k in keyshares]

@election_view
def trustee_home(request, election, trustee_email):
  return HttpResponse("trustees home for election %s" % election.election_id)

@election_view
def trustee_upload_pk(request, election, trustee_email):
  return HttpResponse("trustees upload pk for election %s" % election.election_id)

@election_view
def trustee_tally(request, election, trustee_email):
  return HttpResponse("trustees tally for election %s" % election.election_id)

@election_view
def trustee_upload_decryption_factor(request, election, trustee_email):
  return HttpResponse("trustees upload dec factor for election %s" % election.election_id)

