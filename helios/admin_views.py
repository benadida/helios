"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.http import *
from security import *

from django.contrib import auth

from crypto import algs
import utils
import csv

from models import *
from view_utils import *

@admin_required
def admin_home(request):
  return render_template(request, 'admin_home')
  
@admin_required
def admin_clients(request):
  api_clients = APIClient.objects.all()
  return render_template(request, 'admin_clients', {'clients': api_clients})
  
@admin_required
def admin_client_new(request):
  new_client = APIClient.objects.create(consumer_key = request.POST['consumer_key'], consumer_secret = request.POST['consumer_secret'])
  return HttpResponseRedirect("./")
  
@admin_required
def admin_client_delete(request):
  client= APIClient.objects.get(consumer_key = request.POST['consumer_key'])
  client.delete()
  return HttpResponseRedirect("./")