"""
Create an Election

usage:
python client/creationelection.py ELECTION_NAME election_questions.json voters.csv HELIOS_SERVER API_KEY_FILENAME.json SECRET_KEY_FILENAME.txt
"""

from base import utils
from crypto import algs, electionalgs
from client import heliosclient

import sys

ELECTION_NAME = sys.argv[1]
QUESTIONS_FILE = sys.argv[2]
VOTERS_FILE = sys.argv[3]
HELIOS_SERVER = sys.argv[4]
API_KEY_FILE = sys.argv[5]
SECRET_KEY_FILE = sys.argv[6]

def open_and_read_file(file_path):
  the_file = open(file_path, "r")
  the_content = the_file.read()
  the_file.close()
  return the_content

# parse the json of questions  
print "doing questions"
questions = utils.from_json(open_and_read_file(QUESTIONS_FILE))

print "doing api_key"
# parse the json for api keys
api_key = utils.from_json(open_and_read_file(API_KEY_FILE))

# instantiate the client
# modify variables here
# api_key_file should contain {consumer_key: 'test', consumer_secret: 'test', access_token: '123', access_token_secret : '123'}
helios = heliosclient.HeliosClient(api_key,
                        host = HELIOS_SERVER,
                        port = 80)

# get the El Gamal Parameters
params = helios.params()

# generate a keypair
kp = params.generate_keypair()

# create the election remotely
election_id = helios.election_new(ELECTION_NAME, kp.pk)

print "election ID is " + election_id

# set questions
helios.election_questions_save(election_id, questions)

# upload the voters
import csv
voter_reader = csv.reader(open(VOTERS_FILE))
for voter_row in voter_reader:
  helios.election_voter_add(election_id, name = voter_row[0], email = voter_row[1])
  print "added " + voter_row[1]

# download all the voters, make a list, use it to create the voters_hash
# FIXME: do this later

# freeze it
helios.election_freeze(election_id)

print "election questions set and frozen"

# secret key
sk_file = open(SECRET_KEY_FILE, "w")
sk_file.write(utils.to_json(kp.sk.toJSONDict()))
sk_file.close()