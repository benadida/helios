/*
 * The Cross-Site Messaging based API implementation
 *
 * This is run inside the IFRAME that serves to receive calls
 * 
 * Ben Adida (ben@adida.net)
 */
 
 // register the event for callbacks
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
 
Helios = {};

// get the election
Helios.get_election = function(params, callback) {
  $.getJSON("/elections/" + params['election_key'], callback);
};

// get the voters
Helios.get_election_voters = function(params, callback) {
  $.getJSON("/elections/" + params['election_key'] + "/voters", callback);
};

// get a single voter
Helios.get_election_voter = function(params, callback) {
  $.getJSON("/elections/" + params['election_key'] + "/voters/" + params['voter_key'], callback);
};

// get the result
Helios.get_election_result = function(params, callback) {
  $.getJSON("/elections/" + params['election_key'] + "/result", callback);
};

// get the result proof
Helios.get_election_result_proof = function(params, callback) {
  $.getJSON("/elections/" + params['election_key'] + "/result_proof", callback);
};