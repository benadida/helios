/*
 * This software incorporates components derived from the
 * Secure Remote Password JavaScript demo developed by
 * Tom Wu (tjw@CS.Stanford.EDU).
 *
 * This library is almost entirely re-written by Ben Adida (ben@adida.net)
 * with a BigInt wrapper.
 */

// A wrapper for java.math.BigInteger with some appropriate extra functions for JSON and 
// generally being a nice JavaScript object.

BigInt = Class.extend({
  init: function(value, radix) {
    if (value == null) {
      debugger;
      throw "null value!";
    }
      
    if (BigInt.use_applet) {
      this._java_bigint = BigInt.APPLET.newBigInteger(value, radix);
    } else {
      try {
        this._java_bigint = new java.math.BigInteger(value, radix);
      } catch (e) {
        alert("oy " + e.toString() + " value=" + value + " , radix=" + radix);
      }
    }
  },
  
  toString: function() {
    return this._java_bigint.toString() + "";
  },
  
  toJSONObject: function() {
    // toString is apparently not overridden in IE, so we reproduce it here.
    return this._java_bigint.toString() + "";
  },
  
  add: function(other) {
    return BigInt._from_java_object(this._java_bigint.add(other._java_bigint));
  },
  
  bitLength: function() {
    return this._java_bigint.bitLength();
  },
  
  mod: function(modulus) {
    return BigInt._from_java_object(this._java_bigint.mod(modulus._java_bigint));
  },
  
  equals: function(other) {
    return this._java_bigint.equals(other._java_bigint);
  },
  
  modPow: function(exp, modulus) {
    return BigInt._from_java_object(this._java_bigint.modPow(exp._java_bigint, modulus._java_bigint));
  },
  
  negate: function() {
    return BigInt._from_java_object(this._java_bigint.negate());
  },
  
  multiply: function(other) {
    return BigInt._from_java_object(this._java_bigint.multiply(other._java_bigint));
  },
  
  modInverse: function(modulus) {
    return BigInt._from_java_object(this._java_bigint.modInverse(modulus._java_bigint));
  }
  
});

//
// Some Class Methods
//
BigInt._from_java_object = function(jo) {
  // bogus object
  var obj = new BigInt("0",10);
  obj._java_bigint = jo;
  return obj;
};

BigInt.fromJSONObject = function(s) {
  return new BigInt(s, 10);
};

BigInt.fromInt = function(i) {
  return BigInt.fromJSONObject("" + i);
};

//
// do the applet check
//
function check_applet() {
  /* Is this Netscape 4.xx? */
  var is_ns4 = (navigator.appName == "Netscape" && navigator.appVersion < "5");

  /* Do we need the toString() workaround (requires applet)? */
  var str_workaround = (navigator.appName == "Opera");

  // stuff this in BigInt
  BigInt.is_ie = (navigator.appName == "Microsoft Internet Explorer");

  /* Decide whether we need the helper applet or not */
  var use_applet = BigInt.is_ie || (!is_ns4 && navigator.platform.substr(0, 5) == "Linux") || str_workaround || typeof(java) == 'undefined';

  if(!navigator.javaEnabled()) {
    alert("Java support required for Helios");
  }
  
  return use_applet;
};

BigInt.use_applet = check_applet();

// Set up the pointer to the applet if necessary, and some
// basic Big Ints that everyone needs (0, 1, 2, and 42)
BigInt.setup = function() {
  if(BigInt.use_applet) {
      BigInt.APPLET = document.applets["bigint"];
      if (BigInt.APPLET == null) {
        //setTimeout("BigInt.setup();", 2000);
        //return;
      }
  }

  BigInt.ZERO = new BigInt("0",10);
  BigInt.ONE = new BigInt("1",10);
  BigInt.TWO = new BigInt("2",10);
  BigInt.FORTY_TWO = new BigInt("42",10);
};

// .onload instead of .ready, as I don't think the applet is ready until onload.
// FIXME: something wrong here in the first load
$(document).ready(function() {
    BigInt.setup();
});


