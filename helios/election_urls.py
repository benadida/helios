"""
Helios URLs for Election related stuff

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from helios.views import *
from helios.models import *

urlpatterns = patterns('',
    (r'^$', one_election),

    # manage keyshare related stuff
    (r'^keyshares_manage$', one_election_keyshares_manage),
    (r'^keyshares_tally_manage$', one_election_keyshares_tally_manage),
    
    # election voting-process actions
    (r'^view$', one_election_view),
    (r'^open_submit$', one_election_open_submit),
    (r'^result$', one_election_result),
    (r'^result_proof$', one_election_result_proof),
    (r'^get_voter_by_email$', one_election_get_voter_by_email),
    (r'^get_voter_by_openid$', one_election_get_voter_by_openid),
    (r'^vote$', one_election_vote),
    (r'^bboard$', one_election_bboard),

    # construct election
    (r'^set_pk$', one_election_set_pk),
    (r'^voters_manage$', one_election_voters_manage),
    (r'^voters_bulk_upload$', one_election_voters_bulk_upload),
    (r'^voters_delete$', one_election_voters_delete),
    (r'^voters_email$', one_election_voters_email), 
    (r'^voters_email_2$', one_election_voters_email_2), 
    (r'^set_reg$', one_election_set_reg),
    (r'^archive$', one_election_archive),
    (r'^build$', one_election_build),
    (r'^save_questions$', one_election_save_questions),
    (r'^freeze$', one_election_freeze), # includes freeze_2 as POST target
    (r'^email_trustees$', one_election_email_trustees), # includes email_trustees_2 as POST target
    
    # computing tally
    (r'^compute_tally$', one_election_compute_tally),
    # (r'^drive_tally_chunk$', one_election_drive_tally_chunk),
    (r'^drive_tally$', one_election_drive_tally),
    (r'^set_tally$', one_election_set_tally),
    # (r'^compute_tally_chunk$', one_election_compute_tally_chunk),
    
    # managing voters
    (r'^voters/$', voter_list),
    (r'^voters/add$', voter_add),    
    (r'^voters/(?P<voter_id>[^/]+)/$', one_voter),
    (r'^voters/(?P<voter_id>[^/]+)/delete$', one_voter_delete),
    # submit vote by one voter
    (r'^voters/(?P<voter_id>[^/]+)/submit$', one_voter_submit),

    # managing trustees
    (r'^trustees/$', trustees_list),
    
    # single trustee actions
    (r'^trustees/(?P<trustee_email>[^/]+)/home', trustee_home),
    (r'^trustees/(?P<trustee_email>[^/]+)/upload_pk', trustee_upload_pk),
    (r'^trustees/(?P<trustee_email>[^/]+)/tally', trustee_tally),
    (r'^trustees/(?P<trustee_email>[^/]+)/upload_decryption_factor', trustee_upload_decryption_factor),
    
    
)
