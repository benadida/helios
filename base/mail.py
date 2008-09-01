"""
A Simple Interface to Sending Email

Ben Adida (ben@adida.net)
"""

# needs a rewrite for GAE

import config

try:
  from google.appengine.api import mail
except:
  pass

def no_send(recipient_names, recipient_emails, sender_name, sender_email, subject, body, reply_to=None):
  print "not sending email as per config (GAE update needed to see email)"
    
def simple_send(recipient_names, recipient_emails, sender_name, sender_email, subject, body, reply_to=None):
  for i in range(len(recipient_names)):
    rec_name = recipient_names[i]
    rec_email = recipient_emails[i]

    message = mail.EmailMessage(sender = "%s <%s>" % (sender_name, sender_email),
                                to = "%s <%s>" % (rec_name, rec_email),
                                subject = subject,
                                body = body)
                               
    if reply_to:
      message.reply_to = reply_to
    
    message.send()
  
# don't send email if config says not to
if not config.SEND_MAIL:
    simple_send = no_send
