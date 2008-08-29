"""
A program to verify a Helios ballot.

FIXME: currently broken and NOT updated to the latest API.

This relies only on basic Python (v2.4+) and included modules: urllib2, sha.

Also, this needs the simplejson module for parsing JSON, v1.7.3+
http://pypi.python.org/pypi/simplejson

Ben Adida
ben@adida.net

2008-01-25
"""

import urllib2, simplejson, sha, time, sys, base64

SERVER_URL = "http://heliosvoting.org"

def hash(str):
    """
    A hex SHA1 hash
    """
    return sha.new(str).hexdigest()

def hash_b64(str):
    """
    A base 64 SHA1 hash
    """
    return base64.b64encode(sha.new(str).digest())[:-1]

def encode_answers(available_answers, selected_answers):
    """
    available_answers is an array of names
    selected_answers is an array of array indices
    encoding is: bit position X is available answer X, and its value is 1 if it is selected.
    e.g.: 9 = 1001 in binary means that candidates 0 and 3 are selected.
    """

    positions = range(len(available_answers))
    positions.reverse()
                      
    result = 0
    for pos in positions:
        result <<= 1
        if pos in selected_answers:
            result += 1
    return result

def check_enc(pk, m, r, c):
    """
    check that a message m encrypts to c using randomness r.
    """
    # encode the message
    intermediate = m + 1
    if pow(intermediate, pk['q'], pk['p']) == 1:
        m_cast = intermediate
    else:
        m_cast = -intermediate % pk['p']

    return ((c['alpha'] == pow(pk['g'],r,pk['p'])) and (c['beta'] == ((pow(pk['y'], r, pk['p']) * m_cast) % pk['p'])))

def xgcd(a,b):
    """
    Euclid's Extended GCD algorithm
    """
    mod = a%b

    if mod == 0: return 0,1
    else:
        x,y = xgcd(b, mod)
        return y, x-(y*(a/b))

def modinv(x, p):
    return xgcd(x,p)[0]    

def cast_value(v):
    return int(v)
        
def cast_ciphertext(c):
    new_c= {}
    new_c['alpha'] = cast_value(c['alpha'])
    new_c['beta'] = cast_value(c['beta'])
    return new_c

def http_json_get(relative_url, with_hash = False):
    """
    Fetch the contents of a URL and parse the result as JSON
    """
    req = urllib2.Request(url = SERVER_URL + relative_url)
    f = urllib2.urlopen(req)
    content = f.read()
    parsed_content = utils.from_json(content)

    if with_hash:
        return parsed_content, hash_b64(content)
    else:
        return parsed_content

def get_election(election_id):
    election, election_hash = http_json_get("/election/json?election_id=%s" % election_id, with_hash=True)

    print "Election Fingerprint: %s" % election_hash

    # cast the values for public key
    for field_name in ['p','q','g','y']:
        election['pk'][field_name] = cast_value(election['pk'][field_name])

    return election

def verify_ballot(ballot):
    """
    Verify a single ballot
    """

    start = time.time()
    
    election = get_election(ballot['election_id'])
    questions = election['questions']

    pk = election['pk']
    g = pk['g']
    y = pk['y']

    # compute the hash
    str_to_hash = ",".join(["%s,%s" % (c['alpha'],c['beta']) for c in ballot['encrypted_vote']])
    fingerprint = hash_b64(str_to_hash)
    print "Ballot Fingerprint: %s" % fingerprint

    # go through each question
    for question_num in range(len(questions)):
        question = questions[question_num]
        
        vote = ballot['vote'][question_num]
        encrypted_vote = cast_ciphertext(ballot['encrypted_vote'][question_num])
        randomness = cast_value(ballot['randomness'][question_num])

        if check_enc(pk, encode_answers(question['answers'],vote), randomness, encrypted_vote):
            print "Question #%s - %s: %s" % (question_num + 1, question['short_name'], ",".join([question['answers'][a] for a in vote]))
        else:
            print "Question #%s -- BAD" % (question_num+1)
        
    end = time.time()
    print "TIME: " + str(end-start)


#
# if this program is called from the prompt as
# python HeliosVerifyBallot.py audit.txt
#
if __name__ == '__main__':
    print "verifying your ballot audit"
    
    f = open(sys.argv[1], 'r')
    ballot_content = f.read()
    f.close()

    ballot = utils.from_json(ballot_content)
    verify_ballot(ballot)
