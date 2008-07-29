
//
// Helios Protocols
// 
// ben@adida.net
//
// FIXME: needs a healthy refactor/cleanup based on Class.extend()
//

var UTILS = {};

UTILS.array_remove_value = function(arr, val) {
  var new_arr = [];
  $(arr).each(function(i, v) {
    if (v != val) {
	new_arr.push(v);
    }
  });

  return new_arr;
};

// a function to encode all the answers in a bigint
// the encoding is done with each possible answer as a single bit
// the ordering of the bits is done so that the first candidate is in bit position 0,
// etc... so the ealier the candidate is in the list, the less significant the bit.
UTILS.answers_to_bigint = function(questions, answers) {
    var result = BigInt.ZERO;
    var count = 0;
    $(questions).each(function(q_num, q) {
	    $(q.answers).each(function(a_num, a) {
	      // if we have this answer, then we set the bit to one
	      if ($(answers[q_num]).index(a_num) > -1) {
		      result = result.setBit(count);
	      } else {
		      result = result.clearBit(count);
	      }

	      // next bit position
	      count += 1;
	    });
    });

    return result;
};

UTILS.bigint_to_answers = function(questions, answer_bigint) {
    // same loop, only we're reading the bit now
    var count = 0;
    answers = [];

    $(questions).each(function(q_num, q) {
	
	    answers[q_num] = [];
	
	    $(q.answers).each(function(a_num, a) {
	      // if bit is set, then that candidate is in the list
	      if (answer_bigint.testBit(count))
		      answers[q_num].push(a_num);

	      // next bit position
	      count += 1;
	    });
    });

    return answers;
};

// single question
UTILS.one_q_answers_to_bigint = function(question, answers) {
    var result = BigInt.ZERO;
    var count = 0;
    $(question.answers).each(function(a_num, a) {
	    // if we have this answer, then we set the bit to one
	    if ($(answers).index(a_num) > -1) {
	      result = result.setBit(count);
	    } else {
	      result = result.clearBit(count);
	    }
	
	    // next bit position
	    count += 1;
    });

    return result;
};

UTILS.bigint_to_one_q_answers = function(question, bigint) {
    // same loop, only we're reading the bit now
    var count = 0;
    answers = [];

    $(question.answers).each(function(a_num, a) {
	    // if bit is set, then that candidate is in the list
	    if (bigint.testBit(count))
	      answers.push(a_num);
	
	    // next bit position
	    count += 1;
    });

    return answers;
};

// hash a bunch of ciphertexts
UTILS.hash_ciphertexts = function(ciphertext_list) {
    var str_to_hash = "";
    $(ciphertext_list).each(function(i, ciph) {
	    if (str_to_hash != "")
	      str_to_hash += ",";

	    str_to_hash += ciph.toString();
    });

    return b64_sha1(str_to_hash);
};

UTILS.array_to_email_string = function(arr) {
    var str = "";
    for (var i=0; i<arr.length; i++) {
	    str += arr[i] + "\n";
    }
    return str;
};

HELIOS = {}

// election
HELIOS.Election = Class.extend({
  init: function() {
  },
  
  toJSONObject: function() {
    // the reason we repeat code here is to make JSON do the right thing
    // in terms of ordering the keys. FIXME: get a JSON library that orders keys properly.
    if (this.pk) {
      return {
        election_id : this.election_id, name : this.name, pk: this.pk.toJSONObject(), questions : this.questions,
        voters_hash : this.voters_hash, voting_ends_at : this.voting_ends_at, voting_starts_at : this.voting_starts_at
      };
    } else {
      return {
        election_id : this.election_id, name : this.name, questions : this.questions,
        voters_hash : this.voters_hash, voting_ends_at : this.voting_ends_at, voting_starts_at : this.voting_starts_at
      };      
    }
  },
  
  get_hash: function() {
    return b64_sha1(jQuery.toJSON(this));
  },
  
  toJSON: function() {
    return jQuery.toJSON(this.toJSONObject());
  }
});

HELIOS.Election.fromJSONObject = function(d) {
  var el = new HELIOS.Election();
  el.election_id = d.election_id;
  el.name = d.name; el.voters_hash = d.voters_hash; el.voting_starts_at = d.voting_starts_at; el.voting_ends_at = d.voting_ends_at;
  el.questions = d.questions;
  el.pk = ElGamal.PublicKey.fromJSONObject(d.pk);
  return el;
};

HELIOS.Election.setup = function(election) {
  return ELECTION.fromJSONObject(election);
};


// ballot handling
BALLOT = {};

BALLOT.pretty_choices = function(election, ballot) {
    var questions = election.questions;
    var answers = ballot.answers;

    // process the answers
    var choices = $(questions).map(function(q_num) {
	    return $(answers[q_num]).map(function(dummy, ans) {
	      return questions[q_num].answers[ans];
	    });
    });

    return choices;
};


// open up a new window and do something with it.
UTILS.open_window_with_content = function(content) {
    if (BigInt.is_ie) {
	    w = window.open("");
	    w.document.open("text/plain");
	    w.document.write(content);
	    w.document.close();
    } else {
	    w = window.open("data:text/plain," + encodeURIComponent(content));
    }
};


//
// crypto
//


HELIOS.EncryptedAnswer = Class.extend({
  init: function(question, answer, pk) {    
    // if nothing in the constructor
    if (question == null)
      return;

    // store answer
    this.answer = answer;

    // do the encryption
    var enc_result = this.doEncryption(question, answer, pk);

    this.choices = enc_result.choices;
    this.randomness = enc_result.randomness;
    this.individual_proofs = enc_result.individual_proofs;
    this.overall_proof = enc_result.overall_proof;    
  },
  
  doEncryption: function(question, answer, pk, randomness) {
    var choices = [];
    var individual_proofs = [];
    var overall_proof = null;
    
    // possible plaintexts [0, 1]
    var plaintexts = [new ElGamal.Plaintext(BigInt.ONE, pk, false), new ElGamal.Plaintext(pk.g, pk, false)];
    
    // keep track of whether we need to generate new randomness
    var generate_new_randomness = false;    
    if (!randomness) {
      randomness = [];
      generate_new_randomness = true;
    }
    
    // go through each possible answer and encrypt either a g^0 or a g^1.
    for (var i=0; i<question.answers.length; i++) {
      var index;
      // if this is the answer, swap them so m is encryption 1 (g)
      if (i == answer) {
        plaintext_index = 1;
      } else {
        plaintext_index = 0;
      }

      // generate randomness?
      if (generate_new_randomness) {
        randomness[i] = Random.getRandomInteger(pk.q);        
      }

      choices[i] = ElGamal.encrypt(pk, plaintexts[plaintext_index], randomness[i]);
      
      // generate proof
      if (generate_new_randomness) {
        // generate proof that this ciphertext is a 0 or a 1
        individual_proofs[i] = choices[i].generateDisjunctiveProof(plaintexts, plaintext_index, randomness[i], ElGamal.disjunctive_challenge_generator);        
      }
    }

    if (generate_new_randomness) {
      // we also need proof that the whole thing sums up to the right number
    
      // compute the homomorphic sum of all the options
      var hom_sum = choices[0];
      var rand_sum = randomness[0];
      for (var i=1; i<question.answers.length; i++) {
        hom_sum = hom_sum.multiply(choices[i]);
        rand_sum = rand_sum.add(randomness[i]).mod(pk.q);
      }
    
      // prove that the sum is 1
      overall_proof = hom_sum.generateProof(plaintexts[1], rand_sum, ElGamal.fiatshamir_challenge_generator);
    }
    
    return {
      'choices' : choices,
      'randomness' : randomness,
      'individual_proofs' : individual_proofs,
      'overall_proof' : overall_proof
    }
  },
  
  clearPlaintexts: function() {
    this.answer = null;
    this.randomness = null;
  },
  
  verifyEncryption: function(question, pk) {
    var result = this.doEncryption(question, this.answer, pk, this.randomness);

    // check that we have the same number of ciphertexts
    if (result.choices.length != this.choices.length) {
      return false;      
    }
      
    // check the ciphertexts
    for (var i=0; i<result.choices.length; i++) {
      if (!result.choices[i].equals(this.choices[i])) {
        alert ("oy: " + result.choices[i] + "/" + this.choices[i]);
        return false;
      }
    }
    
    // we made it, we're good
    return true;
  },
  
  toString: function() {
    // get each ciphertext as a JSON string
    var choices_strings = jQuery.makeArray($(this.choices).map(function(i,c) {return c.toString();}));
    return choices_strings.join("|");
  },
  
  toJSON: function() {
    return jQuery.toJSON(this.toJSONObject());
  },
  
  toJSONObject: function(include_plaintext) {
    var return_obj = {
      'choices' : $(this.choices).map(function(i, choice) {
        return choice.toJSONObject();
      }),
      'individual_proofs' : $(this.individual_proofs).map(function(i, disj_proof) {
        return disj_proof.toJSONObject();
      }),
      'overall_proof' : this.overall_proof.toJSONObject()
    };
    
    if (include_plaintext) {
      return_obj['answer'] = this.answer;
      return_obj['randomness'] = $(this.randomness).map(function(i, r) {
        return r.toJSONObject();
      });
    }
    
    return return_obj;
  }
});

HELIOS.EncryptedAnswer.fromJSONObject = function(d, election) {
  var ea = new HELIOS.EncryptedAnswer();
  ea.choices = $(d.choices).map(function(i, choice) {
    return ElGamal.Ciphertext.fromJSONObject(choice, election.pk);
  });
  
  ea.individual_proofs = $(d.individual_proofs).map(function (i, p) {
    return ElGamal.DisjunctiveProof.fromJSONObject(p);
  });
  
  ea.overall_proof = ElGamal.Proof.fromJSONObject(d.overall_proof);
  
  // possibly load randomness and plaintext
  if (d.randomness) {
    ea.randomness = $(d.randomness).map(function(i, r) {
      return BigInt.fromJSONObject(r);
    });
    ea.answer = d.answer;
  }
  
  return ea;
};

HELIOS.EncryptedVote = Class.extend({
  init: function(election, answers) {
    // empty constructor
    if (election == null)
      return;
      
    var n_questions = election.questions.length;
    this.encrypted_answers = [];

    // loop through questions
    for (var i=0; i<n_questions; i++) {
      // get answers[i][0] because we assume a single answer
      this.encrypted_answers[i] = new HELIOS.EncryptedAnswer(election.questions[i], answers[i][0], election.pk);
    }
    
    // keep information about the election around
    this.election_id = election.election_id;
    this.election_hash = election.get_hash();
  },
  
  toString: function() {
    // for each question, get the encrypted answer as a string
    var answer_strings = jQuery.makeArray($(this.encrypted_answers).map(function(i,a) {return a.toString();}));
    
    return answer_strings.join("//");
  },
  
  clearPlaintexts: function() {
    $(this.encrypted_answers).each(function(i, ea) {
      ea.clearPlaintexts();
    });
  },
  
  verifyEncryption: function(questions, pk) {
    var overall_result = true;
    $(this.encrypted_answers).each(function(i, ea) {
      overall_result = overall_result && ea.verifyEncryption(questions[i], pk);
    });
    return overall_result;
  },
  
  toJSONObject: function(include_plaintext) {
    var answers = $(this.encrypted_answers).map(function(i,ea) {
      return ea.toJSONObject(include_plaintext);
    });
    
    return {
      answers : answers,
      election_hash : this.election_hash,
      election_id : this.election_id
    }
  },
  
  toJSON: function() {
    return jQuery.toJSON(this.toJSONObject());
  },
  
  get_hash: function() {
    return b64_sha1(this.toJSON());
  },
  
  get_audit_trail: function() {
    return this.toJSONObject(true);
  },
  
  verifyProofs: function(pk, outcome_callback) {
    // 0 and 1 in exponential el-gamal form.
    ZERO = new ElGamal.Plaintext(BigInt.fromJSONObject("1"), pk);
    ONE = new ElGamal.Plaintext(pk.g, pk);
    
    var VALID_P = true;
    
    // for each question and associate encrypted answer
    $(this.encrypted_answers).each(function(ea_num, enc_answer) {
        var overall_result = 1;

        // go through each individual proof
        // build up the homomorphic product along the way
        $(enc_answer.choices).each(function(choice_num, choice) {
          var result = choice.verifyDisjunctiveProof([ZERO,ONE], enc_answer.individual_proofs[choice_num], ElGamal.disjunctive_challenge_generator);
          outcome_callback(ea_num, choice_num, result, choice);
          
          VALID_P = VALID_P && result;
           
          // keep track of homomorphic product
          overall_result = choice.multiply(overall_result);
        });
        
        // check the proof on the overall product
        var overall_check = overall_result.verifyProof(ONE, enc_answer.overall_proof);
        outcome_callback(ea_num, null, overall_check, null);
        VALID_P = VALID_P && overall_check;
    });
    
    return VALID_P;
  }
});

HELIOS.EncryptedVote.fromJSONObject = function(d, election) {
  var ev = new HELIOS.EncryptedVote();
  
  ev.encrypted_answers = $(d.answers).map(function(i, ea) {
    return HELIOS.EncryptedAnswer.fromJSONObject(ea, election);
  });
  
  ev.election_hash = d.election_hash;
  ev.election_id = d.election_id;
  
  return ev;
};

