"""
Add Voters

usage:
python client/addvoters.py HELIOS_SERVER ELECTION_ID voters.csv API_KEY_FILENAME.json
"""

from base import utils
from crypto import algs, electionalgs
from client import heliosclient

import sys

HELIOS_SERVER = sys.argv[1]
ELECTION_ID = sys.argv[2]
VOTERS_FILE = sys.argv[3]
API_KEY_FILE = sys.argv[4]

def open_and_read_file(file_path):
  the_file = open(file_path, "r")
  the_content = the_file.read()
  the_file.close()
  return the_content

# parse the json for api keys
api_key = utils.from_json(open_and_read_file(API_KEY_FILE))

# instantiate the client
# modify variables here
# api_key_file should contain {consumer_key: 'test', consumer_secret: 'test', access_token: '123', access_token_secret : '123'}
helios = heliosclient.HeliosClient(api_key,
                        host = HELIOS_SERVER,
                        port = 80)

election_id = ELECTION_ID

# upload the voters
import csv
voter_reader = csv.reader(open(VOTERS_FILE))
for voter_row in voter_reader:
  helios.election_voter_add(election_id, name = voter_row[0], email = voter_row[1])
  print "added " + voter_row[1]


