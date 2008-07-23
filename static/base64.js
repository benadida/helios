/* base64.js
 *
 * Description:
 *     Base64 (radix-64) encoding and decoding routines.
 *
 *     See RFC 1521 and 1522, or for a short description
 *     Stallings, William: Data and Computer Communications 
 *     (international edition), 5th Ed. p. 710-713
 *
 * Author: 
 *     Jani Nurminen <jnurmine@lut.fi>
 *
 *
 */

// Look-up tables for encoding and decoding.

// Encoding table
var base64Enc = [
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/', 
	'='
];

// Decoding table (reverse mapping of base64Enc
// using an associative array)
var base64Dec = 
	{'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7,
	 'I': 8, 'J': 9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15,
	 'Q':16, 'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23,
	 'Y':24, 'Z':25, 'a':26, 'b':27, 'c':28, 'd':29, 'e':30, 'f':31,
	 'g':32, 'h':33, 'i':34, 'j':35, 'k':36, 'l':37, 'm':38, 'n':39,
	 'o':40, 'p':41, 'q':42, 'r':43, 's':44, 't':45, 'u':46, 'v':47,
	 'w':48, 'x':49, 'y':50, 'z':51, '0':52, '1':53, '2':54, '3':55,
	 '4':56, '5':57, '6':58, '7':59, '8':60, '9':61, '+':62, '/':63,
	 '=':64};

var PADDING_CHAR = 64;			// index of padding char

/* Encode data into base64 representation. 
 * Parameter:
 * 	data - an array of data to encode
 * Return: base64 encoded data as a String.
 */

function base64Encode (data)
{
	var output    	= new Array();	// total output
	var oc 		= 0;		// index accumulator for output
	var len		= data.length;

	for (var i=0; i < len; /* nothing */ )
	{
		// combine three 8-bit data bytes into
		// create a 24-bit value
		now  = data[i++] << 16;	
		now |= data[i++] << 8;	
		now |= data[i++];	

		// split into four 6-bit values and encode
		output[oc++] = base64Enc[now >>> 18 & 63]; 	// 23..18
		output[oc++] = base64Enc[now >>> 12 & 63]; 	// 17..12
		output[oc++] = base64Enc[now >>> 6  & 63]; 	// 11..6
		output[oc++] = base64Enc[now       & 63]; 	// 5..0
	}

	// pad if necessary
	var padAmount = i - len;

	if (padAmount > 0) 
	{ 
		// previous loop went too far, backtrack
		oc -= padAmount; 
	}		
	
	padAmount = Math.abs(padAmount);	// how much to pad

	while (padAmount-- > 0)
	{
		output[oc++] = base64Enc[PADDING_CHAR];
	}

	return output.join("");
}

/* Decode base64 representation back to data.
 * Parameter:
 * 	data - a String of base64 data to decode
 * Return: decoded data as an Array.
 */

function base64Decode (data)
{
	var output    	= new Array();	// total output
	var oc 		= 0;		// index accumulator for input
	var len		= data.length;	// 0..len-1

	// find the position where the padding starts
	while (data[--len] == base64Enc[PADDING_CHAR]) { /* nothing */ };

	// decode
	for (var i=0; i < len; /* nothing */ )
	{	
		// combine four incoming chars into
		// one 24-bit value and decode
		var now = base64Dec[data[i++]] << 18;	// 23..18
		now    |= base64Dec[data[i++]] << 12;	// 17..12
		now    |= base64Dec[data[i++]] << 6;	// 11..5
		now    |= base64Dec[data[i++]];		// 5..0

		// split into three 8-bit values
		output[oc++] = now >>> 16 & 255; 	// 23..16
		output[oc++] = now >>> 8  & 255; 	// 15..8
		output[oc++] = now        & 255; 	// 7..0
	}

	return output;
}
