"""
A program to verify a Helios election and provide the verified tally.

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

def check_reenc(pk, c1, c2, reenc_factor):
    """
    check that a ciphertext c1 reencrypts to c2 under given pk and reenc factor
    """
    return ((c1['alpha'] * pow(pk['g'], reenc_factor, pk['p'])) % pk['p'] == c2['alpha']) and ((c1['beta'] * pow(pk['y'], reenc_factor, pk['p'])) % pk['p'] == c2['beta'])

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

def decode_answers(available_answers, answer_value):
    """
    available_answers is an array of names
    selected_answers is an array of array indices
    encoding is: bit position X is available answer X, and its value is 1 if it is selected.
    e.g.: 9 = 1001 in binary means that candidates 0 and 3 are selected.
    """

    # convert the int to a list of candidates
    answers = []

    for i in range(len(available_answers)):
      # look at least significant bit
      if answer_value & 1 == 1:
        answers.append(i)

      answer_value >>= 1

    return answers

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

def get_votes(election_id, question_num):
    votes = http_json_get("/election/votes?election_id=%s&question_num=%s" % (election_id, question_num))

    # make sure that all integer values are cast to integers
    for v in votes:
        v['vote']['encrypted_vote'] = cast_ciphertext(v['vote']['encrypted_vote'])

    return votes

def get_shuffled_votes(election_id, question_num):
    shuffled_votes = http_json_get("/election/shuffled_votes?election_id=%s&question_num=%s" % (election_id, question_num))

    # make sure that all integer values are cast to integers
    for v in shuffled_votes:
        v['encrypted_vote'] = cast_ciphertext(v['encrypted_vote'])
        
        # proof items
        for field_name in ['a','b','m','t','chal']:
            v['decryption_proof'][field_name] = cast_value(v['decryption_proof'][field_name])

    return shuffled_votes
    
def get_shuffle_proofs(election_id, question_num):
    shuffle_proofs = http_json_get("/election/shuffle_proofs?election_id=%s&question_num=%s" % (election_id,question_num))

    # generate a hash of the secondary outputs
    secondary_outputs_hash = hash(utils.to_json([sp['secondary_outputs'] for sp in shuffle_proofs]))

    # make sure all integer values are cast to integers
    for sp in shuffle_proofs:
        sp['secondary_outputs'] = [cast_ciphertext(ciph) for ciph in sp['secondary_outputs']]
        sp['reenc_factors'] = [cast_value(v) for v in sp['reenc_factors']]

    return shuffle_proofs, secondary_outputs_hash

def verify_election(election_id):
    """
    Verify the shuffling and decryption of an election
    """

    start = time.time()
    
    election = get_election(election_id)
    questions = election['questions']

    pk = election['pk']
    g = pk['g']
    y = pk['y']

    # tally for all questions and answers
    tally = [[0 for a in q['answers']] for q in questions]

    all_votes = {}
    all_voter_names = {}

    # go through the questions
    for question_num in range(len(questions)):
        question = questions[question_num]
        print "verifying question #%s" % question_num
        
        votes = get_votes(election_id, question_num)

        # keep track of all votes for later hashing
        for v in votes:
            if not all_votes.has_key(v['voter_id']):
                all_votes[v['voter_id']] = []
                all_voter_names[v['voter_id']] = v['name']

            all_votes[v['voter_id']].append(v['vote']['encrypted_vote'])
        
        shuffled_votes = get_shuffled_votes(election_id, question_num)

        # load all the shuffle proofs for this question
        shuffle_proofs, secondary_outputs_hash = get_shuffle_proofs(election_id, question_num)
        
        # cast the challenge hash to an int
        challenge_int = int(secondary_outputs_hash, 16)

        # loop through each proof iteration
        for sp_num in range(len(shuffle_proofs)):
            shuffle_proof = shuffle_proofs[sp_num]
            
            challenge_bit = ((challenge_int >> sp_num) & 1 == 1)

            # check the challenge bit
            if challenge_bit != shuffle_proof['challenge_bit']:
                raise Exception("Challenge Bit doesn't match")
            
            middle_mix = shuffle_proof['secondary_outputs']
            permutation = shuffle_proof['permutation']
            reenc_factors = shuffle_proof['reenc_factors']

            # go through each output in this proof iteration
            # a permutation is e.g. [2,0,1]
            for output_num in range(len(permutation)):
                # side of the audit depends on the challenge bit
                if challenge_bit:
                    c1 = middle_mix[permutation[output_num]]
                    c2 = shuffled_votes[output_num]['encrypted_vote']
                else:
                    c1 = votes[permutation[output_num]]['vote']['encrypted_vote']
                    c2 = middle_mix[output_num]

                # the reenc factor matches the MIX INPUT, *not* OUTPUT, position.
                if check_reenc(pk, c1, c2, reenc_factors[permutation[output_num]]):
                    print "Question #%s, Iteration #%s, Output #%s: OK" % (question_num, sp_num, output_num)
                else:
                    raise Exception("Question #%s, Iteration #%s, Output #%s: BAD" % (question_num, sp_num, output_num))

        # go through decryptions and make sure they are okay
        for sv_num in range(len(shuffled_votes)):
            sv = shuffled_votes[sv_num]
            
            encrypted_vote = sv['encrypted_vote']
            decrypted_vote = sv['decrypted_vote']
            proof = sv['decryption_proof']
        
            # make sure "m" is encoded properly into the q order of Z_p^* generated by g
            y = decrypted_vote['m'] + 1
            if pow(y, pk['q'], pk['p']) == 1:
                m = y
            else:
                m = -y % pk['p']

            if proof['m'] != m:
                raise Exception("Shuffled Vote #%s: encoding doesn't match" % sv_num)
        
            # we are checking log_g y = log_G Y, for G = g^r and Y = y^r
            G = encrypted_vote['alpha']
            Y = (encrypted_vote['beta'] * modinv(m, pk['p'])) % pk['p']

            # check challenge
            computed_chal = int(hash(str(proof['a']) + "," + str(proof['b'])),16)

            if computed_chal != proof['chal']:
                raise Exception("Shufled Vote #%s: bad challenge" % sv_num)
        
            # first check
            if pow(pk['g'], proof['t'], pk['p']) != ((proof['a'] * pow(pk['y'], proof['chal'], pk['p'])) % pk['p']):
                raise Exception("Shuffled Vote #%s: bad first check" % sv_num)

            # second check
            if pow(G, proof['t'], pk['p']) != ((proof['b'] * pow(Y, proof['chal'], pk['p'])) % pk['p']):
                raise Exception("Shuffled Vote #%s: bad second check" % sv_num)

            print "Question #%s / Shuffled Vote #%s: decryption OK" % (question_num, sv_num)

            # tally it
            decoded_vote = decode_answers(question['answers'], sv['decrypted_vote']['m'])

            for a in decoded_vote:
                tally[question_num][a] += 1

    print "Vote Fingerprints"
    for voter_id, votes in all_votes.items():
        voter_name = all_voter_names[voter_id]
        str_to_hash = ",".join(["%s,%s" % (v['alpha'],v['beta']) for v in votes])
        fingerprint = hash_b64(str_to_hash)
        
        print "Voter #%s - %s - %s" % (voter_id, voter_name, fingerprint)

    print "Tally:"
    for question_num in range(len(questions)):
        question = questions[question_num]
        print "Question: %s" % question['short_name']
        for answer_num in range(len(question['answers'])):
            answer = question['answers'][answer_num]
            print "  %s : %s" % (answer, tally[question_num][answer_num])
            
    end = time.time()
    print "TIME: " + str(end-start)


#
# if this program is called from the prompt as
# python HeliosVerifyBallot.py audit.txt
#
if __name__ == '__main__':
    print "verifying the election"

    election_id = sys.argv[1]
    verify_election(election_id)
