"""
Tally Election

usage:
python client/electioninfo.py HELIOS_SERVER ELECTION_ID
"""

from base import utils
from crypto import algs, electionalgs
from client import heliosclient

import sys

HELIOS_SERVER = sys.argv[1]
ELECTION_ID = sys.argv[2]
API_KEY_FILE = sys.argv[3]

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

# load the election 
election = helios.election_get(ELECTION_ID)

print election.toJSONDict()
print utils.to_json(election.toJSONDict())
