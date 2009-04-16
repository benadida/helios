/*
 * The new Helios API, uses cross-frame messaging if needed
 *
 * Ben Adida (ben@adida.net)
 *
 * 2008-08-25
 */
  
// the API if making calls to the same host as where we currently are.
// this also exposes a cross-frame incoming API
_Helios_SameSite = Class.extend({
  init: function() {
    // no initialization necessary here
  },
  
  // register event listeners for cross-frame messaging
  setup: function() {
    // FIXME: make this more jQuery friendly and add something about
    // whether this needs the callback
    if (window.addEventListener) {
      window.addEventListener('message', function(message_evt) {
        // we allow calls from anywhere, but we record where it's from
        var source = message_evt.source;

        // parse the JSON securely
        var call = jQuery.secureEvalJSON(message_evt.data);

        this[call['function']](call['params'], function(result) {
          var response = {'call_id' : call['call_id'], 'result' : result};
          source.postMessage(jQuery.toJSON(response), '*');
        });
      }, false);
    }
  },
  
  getJSON: function(url, callback) {
    // get the JSON manually so that the raw source is still accessible
    $.get(API_PREFIX + url, function(json_str) {
      callback($.secureEvalJSON(json_str), json_str);
    });
  },
  
  get_election: function(params, callback) {
    this.getJSON("/elections/" + params['election_id'] + "?date=" + new Date().getTime(), callback);
  },
  
  get_election_voters: function(params, callback) {
    this.getJSON("/elections/" + params['election_id'] + "/voters?date=" + new Date().getTime(), callback);
  },
  
  get_election_voter: function(params, callback) {
    this.getJSON("/elections/" + params['election_id'] + "/voters/" + params['voter_id'] + "?date=" + new Date().getTime(), callback);
  },
  
  get_election_trustees: function(params, callback) {
    this.getJSON("/elections/" + params['election_id'] + "/trustees/?date=" + new Date().getTime(), callback);
  },
  
  get_election_result: function(params, callback) {
    this.getJSON("/elections/" + params['election_id'] + "/result?date=" + new Date().getTime(), callback);
  },
  
  get_election_result_proof: function(params, callback) {
    this.getJSON("/elections/" + params['election_id'] + "/result_proof?date=" + new Date().getTime(), callback);
  }
});


//
// the cross-site implementation of the API
// 

_Helios_CrossSite = Class.extend({
  init: function() {
    this.CALL_ID = 0;
    this.CALLBACKS = {};
  },
  
  setup : function() {      
    if (!window.postMessage) {
      alert('your browser does not support postMessage... this will not work.');
      return;
    }
      
    this.API_FRAME = document.createElement('iframe');
    this.API_FRAME.src = "http://" + API_HOST + API_PREFIX + "/elections/api";
    this.API_FRAME.style.width=0;
    this.API_FRAME.style.height=0;
    this.API_FRAME.style.border=0;
    
    $(document).ready(function() {
      document.body.appendChild(this.API_FRAME);
    });
      
    // register the event for callbacks
    var self = this;
    window.addEventListener('message', function(message_evt) {
      // make sure it's from the API window
      // FIXME: hmmm, we probably should make sure no one else can navigate
      // it, although this should be okay with the latest Barth/Jackson fixes.
      if (message_evt.source != self.API_FRAME.contentWindow)
        return;
      
      // parse the JSON securely
      var result = jQuery.secureEvalJSON(message_evt.data);
      
      // do the callback
      self.api_return(result['call_id'], result['result']);
    }, false);
  },
  
  'call_api' : function(func, params, callback) {
    var call_id = this.CALL_ID++;
    this.CALLBACKS[call_id] = callback;
    var api_struct = {'call_id' : call_id, 'function' : func, 'params' : params}
    
    // be more precise with target of post message!
    this.API_FRAME.contentWindow.postMessage(jQuery.toJSON(api_struct), '*');
  },
  
  'api_return' : function(call_id, result) {
    var callback = this.CALLBACKS[call_id];
    delete this.CALLBACKS[call_id];

    if (callback)
      callback(result);
  },
  
  get_election: function(params, callback) {
    this.call_api('get_election', params, callback);
  },

  get_election_voters: function(params, callback) {
    this.call_api('get_election_voters', params, callback);  
  },

  get_election_voter: function(params, callback) {
    this.call_api('get_election_voter', params, callback);  
  },

  get_election_trustees: function(params, callback) {
    this.call_api('get_election_trustees', params, callback);  
  },

  get_election_result: function(params, callback) {
    this.call_api('get_election_result', params, callback);
  },

  get_election_result_proof: function(params, callback) {
    this.call_api('get_election_result_proof', params, callback);
  }
});


// Decide whether cross-site or same-site
var host_str = window.location.hostname;
if (window.location.port != 80 && window.location.port != "") {
  host_str += ":" + window.location.port;
}

if (typeof(API_HOST) == 'undefined') {
  API_HOST = 'www.heliosvoting.org';
}

if (host_str == API_HOST) {
  Helios = new _Helios_SameSite();
} else {
  Helios = new _Helios_CrossSite();
}

