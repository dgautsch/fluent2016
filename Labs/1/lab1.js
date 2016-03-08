// Cryptographic functionality for lab 1


// When GenerateKey button is clicked, create a new AES-CBC
// 256 bit key, export it, and put a hex encoding of it in
// the Key input field.
function generateKey() {
	
	console.log('Generating Key');

	window.crypto.subtle.generateKey(
		{name: 'AES-CBC', length: 256}, 
		true, 
		['encrypt', 'decrypt']
	)
	.then(function (key) {
        // Export to ArrayBuffer
        return window.crypto.subtle.exportKey("raw",key);
	})
	.then(function (buf) {
		var byteArray = new Uint8Array(buf);
		var keyField = document.getElementById("key");
		keyField.value = byteArrayToHexString(byteArray);
	})
	.catch(function (err) {
		throw new Error(err.message);
	});
}



// When the Encrypt button is pressed, create a CryptoKey
// object from the hex encoded data in the Key input field,
// then use that key to encrypt the plaintext. Hex encode the
// random IV used and place in the IV field, and base 64 encode
// the ciphertext and place in the Ciphertext field.
function encrypt() {

	console.log('Encrypting Key');
	
    // Start by getting Key and Plaintext into byte arrays
    var keyField = document.getElementById("key");
    var hexString = keyField.value;
    var keyBytes = hexStringToByteArray(hexString);

    var plaintextField = document.getElementById("plaintext");
    var plaintext = plaintextField.value;
    var plaintextBytes = stringToByteArray(plaintext);

    // Make a CryptoKey from the Key string
    window.crypto.subtle.importKey(
        "raw",
        keyBytes,
        {name: "AES-CBC", length: 256},
        false,
        ["encrypt"]
    ).then(function(key){
        // Get a random IV, put in IV field, too
        var iv = window.crypto.getRandomValues(new Uint8Array(16));
        var ivField = document.getElementById("iv");
        var ivHexString = byteArrayToHexString(iv);
        ivField.value = ivHexString;

        // Use the CryptoKey to encrypt the plaintext
        return window.crypto.subtle.encrypt(
            {name: "AES-CBC", iv: iv},
            key,
            plaintextBytes
        );
    }).then(function(ciphertextBuf){
        // Encode ciphertext to base 64 and put in Ciphertext field
        ciphertextBytes = new Uint8Array(ciphertextBuf);
        base64Ciphertext = byteArrayToBase64(ciphertextBytes);
        ciphertextField = document.getElementById("ciphertext");
        ciphertextField.value = base64Ciphertext;
    }).catch(function(err){
        alert("Encryption error: " + err.message);
    });
}


// When the Decrypt button is pressed, create a CryptoKey
// object from the hex encoded data in the Key input field,
// decode the hex IV field value to a byte array, decode
// the base 64 encoded ciphertext to a byte array, and then
// use that IV and key to decrypt the ciphertext. Place the
// resulting plaintext in the plaintext field.
function decrypt() {
    // Start by getting Key, IV, and Ciphertext into byte arrays
    var keyField = document.getElementById("key");
    var keyHexString = keyField.value;
    var keyBytes = hexStringToByteArray(keyHexString);

    var ivField = document.getElementById("iv");
    var ivHexString = ivField.value;
    var ivBytes = hexStringToByteArray(ivHexString);

    var ciphertextField = document.getElementById("ciphertext");
    var ciphertextBase64String = ciphertextField.value;
    var ciphertextBytes = base64ToByteArray(ciphertextBase64String);

    // Make a CryptoKey from the Key string
    window.crypto.subtle.importKey(
        "raw",
        keyBytes,
        {name: "AES-CBC", length: 256},
        false,
        ["decrypt"]
    ).then(function(key){
        // Use the CryptoKey and IV to decrypt the plaintext
        return window.crypto.subtle.decrypt(
            {name: "AES-CBC", iv: ivBytes},
            key,
            ciphertextBytes
        );
    }).then(function(plaintextBuf){
        // Convert array buffer to string and put in Plaintext field
        plaintextBytes = new Uint8Array(plaintextBuf);
        plaintextString = byteArrayToString(plaintextBytes);
        plaintextField = document.getElementById("plaintext");
        plaintextField.value = plaintextString;
    }).catch(function(err){
        alert("Encryption error: " + err.message);
    });
}


// Hints:
//
// SubtleCrypto methods:
//
// window.msCrypto.subtle.generateKey(algorithm, extractable, usages)
//  - returns a CryptoOperation, onsuccess event target.result is CryptoKey
//  - algorithm is an object with a name property, possibly others
//    - name is a registered algorithm name (see spec)
//    - AES-CBC is the name to use here
//    - that algorithm requires a second property: length
//    - use 256 (bits) as the length
//  - extractable is a boolean. Can the key value be exported?
//  - usages is an array of strings. See specs for values in general
//    - ["encrypt", "decrypt"] here.
//
// window.msCrypto.subtle.exportKey(keyFormat, cryptoKey)
// - returns a KeyOperation, onsuccess event target.result is ArrayBuffer
// - keyFormat is one of four strings
//   - "raw" for secret keys
//   - "spki" for public keys
//   - "pkcs8" for private keys
//   - "jwk" for any kind of key
// - cryptoKey is the key to export
//
// window.msCrypto.subtle.importKey(keyFormat, keyBytes, algorithm, exportable, usages)
// - returns a JeyOperation, onsuccess event target.result is CryptoKey
// - keyFormat, algorithm, exportable, usages same as in above methods
// - keyBytes is an ArrayBuffer or byte array with key value
//
// window.msCrypto.subtle.encrypt(algorithm, key, plaintext)
// - returns a CryptoOperation, onsuccess event target.result is ciphertext
// - algorithm object has name and iv properties
//   - name same as used for generateKey and importKey
//   - iv is 16 bytes of random data, needed to maintain security
//   - iv is not secret
// - plaintext is an ArrayBuffer or byte array
//
// window.msCrypto.subtle.decrypt(algorithm, key, ciphertext)
// - returns a CryptoOperation, onsuccess event target.result is plaintext
// - algorithm object has name and iv properties
//   - name same as used for generateKey and importKey
//   - iv must be the same 16 bytes used when encrypting
// - ciphertext is an ArrayBuffer or byte array
