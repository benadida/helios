"""
Helios URLs

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from helios.views import *
from helios.models import *

urlpatterns = patterns('',
    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # basic static stuff
    (r'^$', home),
    (r'^learn$', learn),
    (r'^faq$', faq),
    (r'^about/$', about),

    # user stuff
    (r'^user/$', user_home),
    (r'^user/login$', user_login),
    (r'^user/logout$', user_logout),
    
    # election
    (r'^elections/', include('election_urls')),
    
)
