
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
    return {
      name : this.name, pk : this.pk.toJSONObject(), questions : this.questions,
      voters_hash : this.voters_hash, voting_ends_at : this.voting_ends_at, voting_starts_at : this.voting_starts_at
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
  el = new HELIOS.Election();
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
    // go through each possible answer and encrypt either a g^0 or a g^1.
    this.choices = [];
    this.randomness = [];
    this.individual_proofs = [];
    
    // if nothing in the constructor
    if (question == null)
      return;

    var plaintexts = [new ElGamal.Plaintext(BigInt.ONE, pk, false), new ElGamal.Plaintext(pk.g, pk, false)];
    
    for (var i=0; i<question.answers.length; i++) {
      var index;
      // if this is the answer, swap them so m is encryption 1 (g)
      if (i == answer) {
        plaintext_index = 1;
      } else {
        plaintext_index = 0;
      }

      var choice_num = this.choices.length;
      this.randomness[choice_num] = Random.getRandomInteger(pk.q);
      this.choices[choice_num] = ElGamal.encrypt(pk, plaintexts[plaintext_index], this.randomness[choice_num]);
      
      // generate proof that this ciphertext is a 0 or a 1
      this.individual_proofs[choice_num] = this.choices[choice_num].generateDisjunctiveProof(plaintexts, plaintext_index, this.randomness[choice_num], ElGamal.disjunctive_challenge_generator);
    }
    
    // we also need proof that the whole thing sums up to the right number
    
    // compute the homomorphic sum of all the options
    var hom_sum = this.choices[0];
    var rand_sum = this.randomness[0];
    for (var i=1; i<question.answers.length; i++) {
      hom_sum = hom_sum.multiply(this.choices[i]);
      rand_sum = rand_sum.add(this.randomness[i]).mod(pk.q);
    }
    
    // prove that the sum is 1
    this.overall_proof = hom_sum.generateProof(plaintexts[1], rand_sum, ElGamal.fiatshamir_challenge_generator);
  },
  
  toString: function() {
    // get each ciphertext as a JSON string
    var choices_strings = jQuery.makeArray($(this.choices).map(function(i,c) {return c.toString();}));
    return choices_strings.join("|");
  },
  
  toJSON: function() {
    return jQuery.toJSON(this.toJSONObject());
  },
  
  toJSONObject: function(include_randomness) {
    var return_obj = {
      'choices' : $(this.choices).map(function(i, choice) {
        return choice.toJSONObject();
      }),
      'individual_proofs' : $(this.individual_proofs).map(function(i, disj_proof) {
        return disj_proof.toJSONObject();
      }),
      'overall_proof' : this.overall_proof.toJSONObject()
    };
    
    if (include_randomness) {
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
  
  return ea;
};

HELIOS.EncryptedVote = Class.extend({
  init: function(questions, answers, pk) {
    // empty constructor
    if (questions == null)
      return;
      
    var n_questions = questions.length;
    this.encrypted_answers = [];

    // loop through questions
    for (var i=0; i<n_questions; i++) {
      this.encrypted_answers[i] = new HELIOS.EncryptedAnswer(questions[i], answers[i], pk);
    }
  },
  
  toString: function() {
    // for each question, get the encrypted answer as a string
    var answer_strings = jQuery.makeArray($(this.encrypted_answers).map(function(i,a) {return a.toString();}));
    
    return answer_strings.join("//");
  },
  
  toJSONObject: function() {
    return $(this.encrypted_answers).map(function(i,ea) {
      return ea.toJSONObject();
    });
  },
  
  toJSON: function() {
    return jQuery.toJSON(this.toJSONObject());
  },
  
  get_hash: function() {
    return b64_sha1(this.toJSON());
  },
  
  get_audit_trail: function() {
    return $(this.encrypted_answers).map(function(i,ea) {
      return ea.toJSONObject(true);
    });    
  }
});

HELIOS.EncryptedVote.fromJSONObject = function(d, election) {
  var ev = new HELIOS.EncryptedVote();
  ev.encrypted_answers = $(d).map(function(i, ea) {
    return HELIOS.EncryptedAnswer.fromJSONObject(ea, election);
  });
  
  return ev;
};

