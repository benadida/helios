"""
Django-specific security options
"""

# get authenticated user
def get_user(request):
  if request.user.is_authenticated():
    return request.user
  else:
    return None

