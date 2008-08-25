//
// The client-side implementation of the Helios cross-site API
//
// Ben Adida (ben@adida.net)
//
// 2008-07-18
//

if (typeof(API_HOST) == 'undefined') {
  API_HOST = 'www.heliosvoting.org';
}

// some stuff with state
Helios = (function() {
  var CALL_ID = 0;
  var CALLBACKS = {};
  var READY_P = false;
  
  // add an iframe
  var API_FRAME;
  
  return {
    'setup' : function() {
        var host_str = window.location.hostname;
        if (window.location.port != 80 && window.location.port != "") {
          host_str += ":" + window.location.port;
        }
        
        if (host_str == API_HOST) {
          // set up the cross-site-api-impl
          $.getScript('/static/cross-site-api-impl.js');
          return;
        }
        
        if (!window.postMessage) {
          alert('your browser does not support postMessage... this will not work.');
          return;
        }
        
        API_FRAME = document.createElement('iframe');
        API_FRAME.src = "http://" + API_HOST + "/elections/api";
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
        
        // mark ourselves as ready
        READY_P = true;
    },
    
    'is_ready' : function() {
      return READY_P;
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

Helios.get_election = function(params, callback) {
  Helios.call_api('get_election', params, callback);
};

Helios.get_election_voters = function(params, callback) {
  Helios.call_api('get_election_voters', params, callback);  
};

Helios.get_election_voter = function(params, callback) {
  Helios.call_api('get_election_voter', params, callback);  
};

Helios.get_election_result = function(params, callback) {
  Helios.call_api('get_election_result', params, callback);
};

Helios.get_election_result_proof = function(params, callback) {
  Helios.call_api('get_election_result_proof', params, callback);
};

