"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.http import *

# Create your views here.
def home(request):
  return HttpResponse("foo")
  
def learn(request):
  return HttpResponse("learn")
  
def faq(request):
  return HttpResponse("faq")
  
def about(request):
  return HttpResponse("about")
  
##
## User
##

def user_home(request):
  return HttpResponse("user home")
  
def user_login(request):
  return HttpResponse("user login")
  
def user_logout(request):
  return HttpResponse("user logout")  