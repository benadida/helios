"""
Send Email to Voters

usage:
python client/emailvoters.py HELIOS_SERVER ELECTION_ID API_KEY_FILE.json SUBJECT_FILE.txt BODY_FILE.txt
"""

from base import utils
from crypto import algs, electionalgs
from client import heliosclient

import sys

HELIOS_SERVER = sys.argv[1]
ELECTION_ID = sys.argv[2]
API_KEY_FILE = sys.argv[3]
SUBJECT_FILE = sys.argv[4]
BODY_FILE = sys.argv[5]

def open_and_read_file(file_path):
  the_file = open(file_path, "r")
  the_content = the_file.read()
  the_file.close()
  return the_content

# parse the json for api keys
api_key = utils.from_json(open_and_read_file(API_KEY_FILE))

# instantiate the client
helios = heliosclient.HeliosClient(api_key,
                        host = HELIOS_SERVER,
                        port = 80)

last_voter_id = None
LIMIT = 10

subject = open_and_read_file(SUBJECT_FILE)
body = open_and_read_file(BODY_FILE)

while True:
  print "LAST VOTER ID is %s" % str(last_voter_id)
  
  # send the the email
  res = helios.election_voters_send_email(ELECTION_ID, subject = subject, body = body, after = last_voter_id, limit = LIMIT)
  print "res is " + res

  if res == "DONE":
    break
    
  if len(res) > 100:
    print "PROBLEM!"
    print res
    break
    
  # increment offset by LIMIT, continue
  last_voter_id = res