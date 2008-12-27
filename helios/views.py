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
  user = get_user(request)
  elections = Election.objects.filter(admin = user)
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
    raise Http500('Need a list of trustees or a public key')
  
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
def one_election_result(request, election):
  return HttpResponse("election result %s" % election.election_id)

@election_view
def one_election_result_proof(request, election):
  return HttpResponse("election result proof %s" % election.election_id)

@election_view
def one_election_get_voter_by_email(request, election):
  return HttpResponse("election get voter by email %s" % election.election_id)

@election_view
def one_election_get_voter_by_openid(request, election):
  return HttpResponse("election get voter by openid %s" % election.election_id)

@election_view
def one_election_vote(request, election):
  """
  UI to vote in an election
  """
  return HttpResponse("election vote UI %s" % election.election_id)

@election_view
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  return HttpResponse("election bboard %s" % election.election_id)
  
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
  return HttpResponse("election voters bulk upload %s" % election.election_id)

@election_admin
def one_election_voters_delete(request, election):
  return HttpResponse("election voters delete %s" % election.election_id)

@election_admin
def one_election_voters_email(request, election):
  return HttpResponse("election voters email %s" % election.election_id)

@election_admin
def one_election_set_reg(request, election):
  return HttpResponse("election voters set_reg %s" % election.election_id)

@election_admin
def one_election_archive(request, election):
  return HttpResponse("election archive %s" % election.election_id)

@election_admin
def one_election_build(request, election):
  return render_template(request, 'election_build', {'election': election})

@election_admin
def one_election_save_questions(request, election):
  import pdb; pdb.set_trace()
  election.questions = utils.from_json(request.POST['questions_json']);
  election.save()

  # always a machine API
  return SUCCESS

@election_admin
def one_election_freeze(request, election):
  return HttpResponse("election freeze %s" % election.election_id)

@election_admin
def one_election_email_trustees(request, election):
  return HttpResponse("election email trustees %s" % election.election_id)

@election_admin
def one_election_compute_tally(request, election):
  return HttpResponse("election compute tally %s" % election.election_id)

@election_admin
def one_election_drive_tally_chunk(request, election):
  return HttpResponse("election drive tally chunk %s" % election.election_id)

@election_admin
def one_election_drive_tally(request, election):
  return HttpResponse("election drive tally %s" % election.election_id)

@election_admin
def one_election_set_tally(request, election):
  return HttpResponse("election set tally %s" % election.election_id)

@election_admin
def one_election_compute_tally_chunk(request, election):
  return HttpResponse("election compute tally chunk %s" % election.election_id)

# Individual Voters
@election_view
def voter_list(request, election):
  return HttpResponse("voter list for election %s" % election.election_id)

@election_admin
def voter_add(request, election):
  v = Voter.objects.create(election = election, email = request.POST['email'], name = request.POST['name'], 
                            category = request.POST['category'])
  v.generate_password()
  v.save()

  return HttpResponseRedirect("../voters_manage")

@election_view
def one_voter(request, election, voter_id):
  return HttpResponse("one voter for election %s" % election.election_id)

@election_admin
def one_voter_delete(request, election, voter_id):
  return HttpResponse("voter delete for election %s" % election.election_id)

@election_view
def one_voter_submit(request, election, voter_id):
  return HttpResponse("voter submit for election %s" % election.election_id)
  
# Trustees
@election_view
def trustees_list(request, election):
  return HttpResponse("trustees list for election %s" % election.election_id)

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

