from django.http import *
from django.core.urlresolvers import reverse
from django.contrib import auth

from oauthclient import client

CONSUMER_KEY = 'eKxAAH0YEvdTzGJJg9XEw'
CONSUMER_SECRET = 'oDYN0ftaVcnU8yGV89QpEbg890JjXVZu25nAl2o'
TWITTER_CLIENT = client.TwitterOAuthClient(CONSUMER_KEY, CONSUMER_SECRET)

# Create your views here.
def start(request):
  tok = TWITTER_CLIENT.get_request_token()
  request.session['request_token'] = tok
  url = TWITTER_CLIENT.get_authenticate_url(tok['oauth_token']) 
  return HttpResponseRedirect(url)

def after(request):
  tok = request.session['request_token']
  twitter_client = client.TwitterOAuthClient(CONSUMER_KEY, CONSUMER_SECRET, tok['oauth_token'], tok['oauth_token_secret'])
  access_token = twitter_client.get_access_token()
  request.session['access_token'] = access_token
  return HttpResponseRedirect("./stuff")

def _get_client(request):
  access_token = request.session['access_token']
  return client.TwitterOAuthClient(CONSUMER_KEY, CONSUMER_SECRET, access_token['oauth_token'], access_token['oauth_token_secret'])

def stuff(request):
  twitter_client = _get_client(request)
  result = twitter_client.oauth_request('https://twitter.com/account/verify_credentials.xml', args={}, method='GET')
  return HttpResponse(result)

def post(request):
  twitter_client = _get_client(request)
  result = twitter_client.oauth_request('https://twitter.com/statuses/update.xml', args={'status':'trying to post...'}, method='POST')
  return HttpResponse(result)