var buf = new Uint8Array(16);
var crypto = window.crypto;
crypto.getRandomValues(buf);


// called sublte because many of these algorithms have subtle usage requirements

/**
 * All methods areasynchronous.
 * Return promises instead of using callbacks.
 * 
 * Use 8 bit arrays only. Otherwise you'll run into issues with other browsers.
 * 
 * The API only supports AES block ciphers. 
 * 256 bit encryption is more secure but is slower than 128 bit encyrption.
 *
 */


var p = crypto.subtle.generateKey({
	name: 'AES-CBC',
	length: 256
}, ['encrypt', 'decrypt']);

p.then(function(result) {
	var key = result;
	return key;
});