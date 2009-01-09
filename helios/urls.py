"""
Helios URLs

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from helios.views import *
from helios.admin_views import *

from helios.models import *

urlpatterns = patterns('',
    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # basic static stuff
    (r'^helios_test$', test),
    (r'^$', home),
    (r'^learn$', learn),
    (r'^faq$', faq),
    (r'^about/$', about),

    # user stuff
    (r'^user/$', user_home),
    (r'^user/logout$', user_logout),
    
    # election
    (r'^elections/params$', election_params),
    (r'^elections/keygenerator$', election_keygenerator),
    (r'^elections/verifier$', election_verifier),
    (r'^elections/single_ballot_verifier$', election_single_ballot_verifier),
    (r'^elections/api$', election_js_api),
    (r'^elections/new$', election_new),
    (r'^elections/new_2$', election_new_2),
    (r'^elections/new_3$', election_new_3),
    
    (r'^elections/(?P<election_id>[^/]+)/', include('helios.election_urls')),
    
    # admin
    (r'^admin/$', admin_home),
    (r'^clients/$', admin_clients),
    (r'^clients/new$', admin_client_new),
    (r'^clients/delete$', admin_client_delete),
    
    # static hack -- production should bypass this route
    # static
    (r'^static/(?P<path>.*)$', 'django.views.static.serve',
            {'document_root': '/web/dev-helios/static'}),

    # accounts
    (r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name': 'login.html'}),

    
)
