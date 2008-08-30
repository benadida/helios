"""
A tally program for Helios

Ben Adida
2008-08-30
"""

from base import oauth
from crypto import algs

import oauthclient
    
consumer = oauth.OAuthConsumer('votehere','votehere')
token = oauth.OAuthToken('123','123')
moc = oauthclient.MachineOAuthClient(consumer, token, 'localhost', 8082)

print moc.access_resource("GET", "/elections/test", {})
    