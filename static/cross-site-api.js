//
// The client-side implementation of the Helios cross-site API
//
// Ben Adida (ben@adida.net)
//
// 2008-07-18
//


// some stuff with state
Helios = (function() {
  var CALL_ID = 0;
  var CALLBACKS = {};
  
  // add an iframe
  var API_FRAME;
  
  return {
    'setup' : function() {   
        API_FRAME = document.createElement('iframe');
        API_FRAME.src = "/elections/api";
        API_FRAME.style.width=0;
        API_FRAME.style.height=0;
        API_FRAME.style.border=0;
        $(document).ready(function() {
          document.body.appendChild(API_FRAME);
        });
        
        // register the event for callbacks
        window.addEventListener('message', function(message_evt) {
          // make sure it's from the API window
          // FIXME: hmmm, we probably should make sure no one else can navigate
          // it, although this should be okay with the latest Barth/Jackson fixes.
          if (message_evt.source != API_FRAME.contentWindow)
            return;
        
          // parse the JSON securely
          var result = jQuery.secureEvalJSON(message_evt.data);
        
          // do the callback
          Helios.api_return(result['call_id'], result['result']);
        }, false);
    },
    
    'call_api' : function(func, params, callback) {
      var call_id = CALL_ID++;
      CALLBACKS[call_id] = callback;
      var api_struct = {'call_id' : call_id, 'function' : func, 'params' : params}
      
      // be more precise with target of post message!
      API_FRAME.contentWindow.postMessage(jQuery.toJSON(api_struct), '*');
    },
    
    'api_return' : function(call_id, result) {
      var callback = CALLBACKS[call_id];
      delete CALLBACKS[call_id];

      if (callback)
        callback(result);
    }
  }
})();

Helios.get_election = function(election_key, callback) {
  Helios.call_api('get_election', {'election_key' : election_key}, function(el_json_obj) {
    callback(HELIOS.Election.fromJSONObject(el_json_obj));
  });
};

Helios.get_election_voters = function(election_key, callback) {
  Helios.call_api('get_election_voters', {'election_key' : election_key}, callback);  
};

Helios.get_election_voter = function(election_key, voter_key, callback) {
  Helios.call_api('get_election_voter', {'election_key' : election_key, 'voter_key' : voter_key}, callback);  
};

Helios.get_election_result = function(election_key, callback) {
  Helios.call_api('get_election_result', {'election_key' : election_key}, callback);
};

Helios.get_election_result_proof = function(election_key, callback) {
  Helios.call_api('get_election_result_proof', {'election_key' : election_key}, callback);
};