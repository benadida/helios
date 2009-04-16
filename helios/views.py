"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.http import *
from django.core.urlresolvers import reverse
from django.contrib import auth

import csv

from security import *
from crypto import algs
import utils
from models import *
from view_utils import *


# Parameters for everything
ELGAMAL_PARAMS = algs.ElGamal()
ELGAMAL_PARAMS.p = 169989719781940995935039590956086833929670733351333885026079217526937746166790934510618940073906514429409914370072173967782198129423558224854191320917329420870526887804017711055077916007496804049206725568956610515399196848621653907978580213217522397058071043503404700268425750722626265208099856407306527012763L
ELGAMAL_PARAMS.q = 84994859890970497967519795478043416964835366675666942513039608763468873083395467255309470036953257214704957185036086983891099064711779112427095660458664710435263443902008855527538958003748402024603362784478305257699598424310826953989290106608761198529035521751702350134212875361313132604049928203653263506381L
ELGAMAL_PARAMS.g = 68111451286792593845145063691659993410221812806874234365854504719057401858372594942893291581957322023471947260828209362467690671421429979048643907159864269436501403220400197614308904460547529574693875218662505553938682573554719632491024304637643868603338114042760529545510633271426088675581644231528918421974L

# trying new ones from OlivierP
ELGAMAL_PARAMS.p = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071L
ELGAMAL_PARAMS.q = 61329566248342901292543872769978950870633559608669337131139375508370458778917L
ELGAMAL_PARAMS.g = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533L



def test(request):
  str = ["%s : %s\n" % (k,request.META[k]) for k in request.META.keys()]
  str += "\n\n request.path_info is %s " % request.path_info
  return HttpResponse(str)
  
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
  return HttpResponseRedirect(reverse(home))
  
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
  
def election_keygenerator(request):
  """
  A key generator with the current params, like the trustee home but without a specific election.
  """
  eg_params_json = utils.to_json(ELGAMAL_PARAMS.toJSONDict())
  return render_template(request, "election_keygenerator", {'eg_params_json': eg_params_json})


@login_required
def election_new(request):
  return render_template(request, "election_new")

@login_required
def election_new_2(request):
  return render_template(request, "election_new_2", {'eg_params_json' : utils.to_json(ELGAMAL_PARAMS.toJSONDict()),
                                                    'name': request.GET['name'], 'election_type': request.GET['election_type']})
                                                      
@login_required
def election_new_3(request):
  """
  Create the new election.
  
  trustees is a JSON list
  """
  
  name = request.POST['name']

  if request.POST.has_key('trustee_list'):
    trustee = request.POST['trustee_list'].split(",")
  else:
    trustee = request.POST.getlist('trustee')
    
  public_key = request.POST.get('public_key', None)
  private_key = request.POST.get('private_key', None)
  voting_starts_at = request.POST.get('voting_starts_at', None)
  voting_ends_at = request.POST.get('voting_ends_at', None)
  
  # election type is homomorphic. The type of the election determines
  # how votes are tallied and verified.
  ballot_type = request.POST.get('ballot_type', 'homomorphic')
  tally_type = request.POST.get('tally_type', 'homomorphic')
  
  # we need a list of admins, or at least a public key
  if len(trustee) == 0 and not public_key:
    return HttpResponseServerError('Need a list of trustees or a public key')
  
  # create an election
  if public_key and public_key != "":
    pk = algs.EGPublicKey.from_dict(utils.from_json(public_key))
  else:
    pk = None
    
  if private_key and private_key != "":
    sk = algs.EGSecretKey.from_dict(utils.from_json(private_key))
  else:
    sk = None
    
  election = Election.objects.create(ballot_type = ballot_type, tally_type = tally_type, name = name,
                      admin = get_user(request), api_client= get_api_client(request),
#                      voting_starts_at = utils.string_to_datetime(voting_starts_at),
#                      voting_ends_at = utils.string_to_datetime(voting_ends_at),
                      public_key = pk, private_key = sk)
  
  ## FIXME: transaction!
  
  # go through the trustees
  if len(trustee) > 0:
    for t in trustee:
      if t.strip() == "":
        continue
      # create the keyshare
      keyshare = KeyShare.objects.create(election = election, email = t)
      keyshare.generate_password()
      keyshare.save()
      
    # send out the email
    ## NO LONGER BY DEFAULT - must send the mail manually
    # send_trustees_email(election, 'Trustee for Election %s' % election.name, 'You have been designated as a trustee of the Helios Election "%s".' % election.name)
  
  # user or api_client?
  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_view, args=[election.election_id]))
  else:
    return HttpResponse(str(election.election_id))

##
## Specific election features
##

@election_admin()
def one_election_keyshares_manage(request, election):
  keyshares = election.get_keyshares()
  ready_p = True
  for keyshare in keyshares:
    ready_p = ready_p and (keyshare.public_key != None)
  return render_template(request, "keyshares_manage", {'election' : election, 'keyshares': keyshares, 'ready_p': ready_p})

@election_admin()
def one_election_keyshares_tally_manage(request, election):
  election_pk_json = utils.to_json(election.public_key.toJSONDict())
  keyshares = election.get_keyshares()
  
  ready_p = True
  for keyshare in keyshares:
    ready_p = ready_p and (keyshare.decryption_factors != None)
  
  return render_template(request,"keyshares_tally_manage", {'election': election, 'election_pk_json': election_pk_json, 'ready_p' : ready_p})
  
  
@election_view()
@json
def one_election(request, election):
  return election.toElection().toJSONDict()

@election_view()
def one_election_view(request, election):
  user = get_user(request)
  admin_p = user_can_admin_election(user, election)
  election_obj = election.toElection()
  return render_template(request, 'election_view', {'election' : election, 'election_obj' : election_obj, 'admin_p': admin_p})

@login_required
@election_view(frozen=True,newvoters=True)
def one_election_open_submit(request, election):
  api_client = get_api_client(request)
  
  if not api_client or election.api_client != api_client:
    logging.info(api_client)
    raise PermissionDenied()
  
  # API client is authenticated to manage this election
  
  # see if there is already a voter for this email and/or openid_url
  try:
    voter= Voter.selectByEmailOrOpenID(election, request.POST.get('email',None), request.POST.get('openid_url',None))

    # set parameters that may be updates to the existing voter
    voter.email = request.POST.get('email',None)
    voter.openid_url = request.POST.get('openid_url', None)
    voter.name = request.POST.get('name', None)
    voter.category = request.POST.get('category', None)
    voter.save()    
  except Voter.DoesNotExist:
    voter = Voter.objects.create(election = election, email=request.POST.get('email',None), openid_url = request.POST.get('openid_url',None),
                        name=request.POST.get('name',None), category=request.POST.get('category',None))
  
  # set the encrypted vote
  voter.set_encrypted_vote(request.POST['encrypted_vote'])
    
  return HttpResponse(voter.voter_id)
  
@election_view()
@json
def one_election_result(request, election):
  return election.result

@election_view()
@json
def one_election_result_proof(request, election):
  return election.decryption_proof
  

@election_view()
@json
def one_election_get_voter_by_email(request, election):
  return Voter.objects.get(election = election, email = request.GET['email']).toJSONDict()

@election_view()
def one_election_get_voter_by_openid(request, election):
  return HttpResponse("election get voter by openid %s" % election.election_id)

@election_view(frozen=True)
def one_election_vote(request, election):
  """
  UI to vote in an election
  """
  return render_template(request, "vote", {'election': election})

@election_view(frozen=True)
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  offset = int(request.GET.get('offset', 0))
  limit = int(request.GET.get('limit', 20))

  if not election.is_frozen():
    return HttpResponseRedirect(reverse(one_election_view, args=[election.election_id]))
    
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
  
@election_admin()
def one_election_voters_manage(request, election):
  voters = election.get_voters()
  voters_json = utils.to_json([v.toJSONDict() for v in voters])
  
  return render_template(request, "election_voters_manage", {'voters_json' : voters_json, 'voters': voters,'election': election})

@election_admin(newvoters=True)
def one_election_voters_bulk_upload(request, election):
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
    
  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_voters_manage, args=[election.election_id]))
  else:
    return SUCCESS
  
@election_admin(frozen=False)
def one_election_voters_delete(request, election):
  voter_id_list = request.POST['voter_ids'].split(",")
  voters = [Voter.objects.get(voter_id = voter_id) for voter_id in voter_id_list]
  for voter in voters:
    if election != voter.election:
      return HttpResponseServerError('bad voter')

  for voter in voters:
    voter.delete()
    
  return SUCCESS

@election_admin(frozen=True)
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

@election_admin(frozen=True)
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
  if get_user(request):
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
""" % (settings.SERVER_HOST + reverse(one_election_view, args=[election.election_id]), settings.SERVER_HOST + reverse(one_election_vote, args=[election.election_id]), election.toElection().get_hash(), voter.email, voter.password, sender_email)

    message = message_header
    message += unicode(request.POST['introductory_message'])
    message += message_footer

    utils.send_email("%s <%s>" % ("Helios", sender_email), ["%s <%s>" % (voter.name, voter.email)], "Voting in Election %s" % election.name, message)
    
    last_id = voter.voter_id
      
    # did we get less than the limit? if so, done
    if limit and len(voters) < limit:
      last_id = None

  # hack for now, no more batching
  return HttpResponse(last_id or "DONE")

@election_admin(frozen=False)
def one_election_set_reg(request, election):
  """
  Set whether this is open registration or not
  """
  open_p = bool(int(request.POST['open_p']))
  election.openreg_enabled = open_p
  election.save()
  
  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_voters_manage, args=[election.election_id]))
  else:
    return SUCCESS

@election_admin()
def one_election_archive(request, election):
  
  archive_p = request.GET.get('archive_p', True)
  
  if bool(int(archive_p)):
    election.archived_at = datetime.datetime.utcnow()
  else:
    election.archived_at = None
  election.save()

  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_view, args=[election.election_id]))
  else:
    return SUCCESS

@election_admin(frozen=False)
def one_election_build(request, election):
  return render_template(request, 'election_build', {'election': election})

@election_admin(frozen=False)
def one_election_save_questions(request, election):
  election.questions = utils.from_json(request.POST['questions_json']);
  election.save()

  # always a machine API
  return SUCCESS

@election_admin(frozen=False)
def one_election_set_pk(request, election):
  if election.public_key:
    return HttpResponseServerError("failure: Public Key exists already")
  
  election.public_key = algs.EGPublicKey.fromJSONDict(utils.from_json(request.POST['public_key_json']))
  election.save()
  
  return SUCCESS
  
@election_admin(frozen=False)
def one_election_freeze(request, election):
  if request.method == "GET":
    return render_template(request, 'election_freeze', {'election': election})
  else:
    election.freeze()

    if get_user(request):
      return HttpResponseRedirect(reverse(one_election_view, args=[election.election_id]))
    else:
      return SUCCESS    

def send_trustees_email(election, subject, body):
  trustees = election.get_keyshares()
  footer_template = """
Your Trustee homepage for election "%s" is:
%s

Your password is:
%s

--
The Helios Voting System
"""

  for trustee in trustees:
    footer = footer_template % (election.name, reverse(trustee_home, args=[election.election_id, trustee.email]), trustee.password)
    
    full_body = body + footer

    # send out the emails for the shares
    utils.send_email("%s <%s>" % ("Helios", "system@heliosvoting.org"), ["%s <%s>" % (trustee.email, trustee.email)], subject, full_body)

@election_admin()
def one_election_email_trustees(request, election):
  if request.method == "GET":
    keyshares = election.get_keyshares()
    return render_template(request, 'email_trustees', {'election' : election,'keyshares': keyshares})
  else:
    body = request.POST['body']
    subject = "Trustee Information for %s" % election.name

    send_trustees_email(election, subject, body)

    return "DONE"

@election_admin(frozen=True)
def one_election_compute_tally(request, election):
  if election.tally_type != "homomorphic":
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))

  return HttpResponse("election compute tally %s" % election.election_id)

@election_admin(frozen=True)
def one_election_drive_tally(request, election):
  """
  JavaScript-based driver for the entire tallying process, now done in JavaScript.
  """
  if election.tally_type != "homomorphic":
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))
  
  election_pk = election.public_key
  election_pk_json = utils.to_json(election_pk.toJSONDict())
  
  election_sk = election.private_key
  if election_sk:
    election_sk_json = utils.to_json(election_sk.toJSONDict())
  else:
    election_sk_json = None
  
  return render_template(request, 'drive_tally', {'election': election, 'election_pk_json' : election_pk_json, 'election_sk_json' : election_sk_json})

@election_admin(frozen=True)
def one_election_set_tally(request, election):
  """
  Set the tally and proof.
  """
  tally_obj = utils.from_json(request.POST['tally'])
  election.set_result(tally_obj['result'], tally_obj['result_proof'])
  election.save()
  
  return SUCCESS

# Individual Voters
@election_view()
@json
def voter_list(request, election):
  # normalize limit
  limit = int(request.GET.get('limit', 500))
  if limit > 500: limit = 500
    
  voters = election.get_voters(category= request.GET.get('category', None), after=request.GET.get('after',None), limit= limit)
  return [v.toJSONDict(with_vote=request.GET.get('with_vote')) for v in voters]
  

@election_admin(newvoters=True)
def voter_add(request, election):
  v = Voter.objects.create(election = election, email = request.POST['email'], name = request.POST['name'], 
                            category = request.POST['category'])
  v.generate_password()
  v.save()

  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_voters_manage, args=[election.election_id]))
  else:
    return SUCCESS

@election_view()
@json
def one_voter(request, election, voter_id):
  """
  View a single voter's info as JSON.
  """
  voter = Voter.objects.get(voter_id = voter_id)
  return voter.toJSONDict(with_vote=True)  

@election_admin(frozen=False)
def one_voter_delete(request, election, voter_id):
  try:
    voter = Voter.objects.get(voter_id = voter_id)
    voter.delete()
  except Voter.DoesNotExist:
    logging.info("no voter")

  if get_request(user):
    return HttpResponseRedirect(reverse(one_election_voters_manage, args=[election.election_id]))
  else:
    return SUCCESS

@election_view(frozen=True)
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

  utils.send_email("%s <%s>" % ("Helios", "system@heliosvoting.org"), ["%s <%s>" % (voter.name, voter.email)], "your vote was recorded", mail_body)

  return SUCCESS  

##
## Trustee Stuff
##

@election_view()
@json
def trustees_list(request, election):
  keyshares = election.get_keyshares()
  return [k.toJSONDict() for k in keyshares]

@election_view()
def trustee_home(request, election, trustee_email):
  eg_params_json = utils.to_json(ELGAMAL_PARAMS.toJSONDict())
  keyshare = KeyShare.objects.get(election=election, email=trustee_email)
  return render_template(request, "trustee_home", {'election': election, 'keyshare': keyshare, 'eg_params_json': eg_params_json})

@election_view(frozen=False)
def trustee_upload_pk(request, election, trustee_email):
  keyshare = KeyShare.objects.get(election=election, email=trustee_email)

  # is this authenticated properly, first api_client, otherwise password?
  api_client = get_api_client(request)
  if not api_client_can_admin_election(api_client, election):
    if keyshare.password != request.POST['password']:
      return HttpResponseServerError("failure: bad password")
    
  election.public_key = None
  election.save()
  
  keyshare.public_key = algs.EGPublicKey.fromJSONDict(utils.from_json(request.POST['public_key']))
  keyshare.pok = utils.from_json(request.POST['pok'])
  keyshare.save()
  return SUCCESS
  

@election_view(frozen=True)
def trustee_tally(request, election, trustee_email):
  keyshare = KeyShare.objects.get(election=election, email=trustee_email)
  election_pk_json = utils.to_json(election.public_key.toJSONDict())
  return render_template(request, "trustee_tally", {'election' : election, 'election_pk_json': election_pk_json, 'keyshare': keyshare})

@election_view(frozen=True)
def trustee_upload_decryption_factor(request, election, trustee_email):
  keyshare = KeyShare.objects.get(election=election, email=trustee_email)
  if keyshare.password != request.POST['password']:
    return "failure: password doesn't match"
    
  keyshare.decryption_factors = utils.from_json(request.POST['decryption_factors'])
  keyshare.decryption_proofs = utils.from_json(request.POST['decryption_proofs'])
  keyshare.save()
  return SUCCESS
  
