/*
 * The Cross-Site Messaging based API implementation
 *
 * This is run inside the IFRAME that serves to receive calls
 * 
 * Ben Adida (ben@adida.net)
 */
  
Helios = {};

// register the event for callbacks
Helios.setup_api= function() {
  window.addEventListener('message', function(message_evt) {
    // we allow calls from anywhere, but we record where it's from
    var source = message_evt.source;
     
    // parse the JSON securely
    var call = jQuery.secureEvalJSON(message_evt.data);
     
    Helios[call['function']](call['params'], function(result) {
      var response = {'call_id' : call['call_id'], 'result' : result};
      source.postMessage(jQuery.toJSON(response), '*');
    });
  }, false);
};

// get the election
Helios.get_election = function(params, callback) {
  $.getJSON("/elections/" + params['election_id'] + "?date=" + new Date().getTime(), callback);
};

// get the voters
Helios.get_election_voters = function(params, callback) {
  $.getJSON("/elections/" + params['election_id'] + "/voters?date=" + new Date().getTime(), callback);
};

// get a single voter
Helios.get_election_voter = function(params, callback) {
  $.getJSON("/elections/" + params['election_id'] + "/voters/" + params['voter_id'] + "?date=" + new Date().getTime(), callback);
};

// get the result
Helios.get_election_result = function(params, callback) {
  $.getJSON("/elections/" + params['election_id'] + "/result?date=" + new Date().getTime(), callback);
};

// get the result proof
Helios.get_election_result_proof = function(params, callback) {
  $.getJSON("/elections/" + params['election_id'] + "/result_proof?date=" + new Date().getTime(), callback);
};

Helios.is_ready = function() {
  return true;
};
