"""
OAuth Client for Helios

Ben Adida
2008-08-30
"""

from helios import oauth, utils

import httplib

# OAuthClient is a worker to attempt to execute a request
class MachineOAuthClient(object):

  SIG_METHOD = oauth.OAuthSignatureMethod_HMAC_SHA1()
  
  def __init__(self, oauth_consumer, oauth_token, server, port):
    self.consumer = oauth_consumer
    self.token = oauth_token
    self.server = server
    self.port = port

  def access_resource(self, method, url, parameters):
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self.token, http_method=method, http_url=url, parameters=parameters)
    oauth_request.sign_request(MachineOAuthClient.SIG_METHOD, self.consumer, self.token)

    headers = oauth_request.to_header()
    if parameters == {}:
      headers['Content-Length'] = 0
      
    #print "headers: " + str(headers)
      
    connection = httplib.HTTPConnection("%s:%d" % (self.server, self.port))
    connection.request(method, url, headers= headers, body = utils.dictToURLParams(parameters))
    response = connection.getresponse()
    return response.read()
