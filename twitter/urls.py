"""
Helios Twitter URLs

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from twitter.views import *

urlpatterns = patterns('',
    # basic static stuff
    (r'^start$', start),
    (r'^after$', after),
    (r'^stuff$', stuff),
    (r'^post$', post),
)
