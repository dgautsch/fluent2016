// Cryptographic functionality for lab 3


// When the Generate Key Pair button is clicked, generate a
// random RSASSA-PKCS1-v1_5 key pair. Export the public and
// private keys (using "spki" and "pkcs8" formats), and put
// the base 64 encoding of those values in the appropriate
// boxes.




function createKeyPair() {
	function exportKey(buffer, type) {
		var keyBytes = new Uint8Array(buffer);
		var keyString = byteArrayToBase64(keyBytes);
		var keyBox = document.getElementById(type);
		keyBox.value = keyString;
	}
	// Replace this alert with the correct code
	window.crypto.subtle.generateKey({
			name: 'RSASSA-PKCS1-v1_5',
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]), // 65537
			hash: {
				name: "SHA-256"
			}

		}, true, ['sign', 'verify']).then(function (keyPair) {

			window.crypto.subtle.exportKey('spki', keyPair.publicKey)
				.then(function(spkiBuffer){exportKey(spkiBuffer, 'publickey')})
				.catch(function (err) {
					alert("Could not export public key: " + err.message);
				});

			window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
				.then(function(pkcs8buffer){exportKey(pkcs8buffer, 'privatekey')})
				.catch(function (err) {
					alert("Could not export public key: " + err.message);
				});

		})
		.catch(function (err) {
			throw new Error(err.message);
		})
}

// When the Sign button is clicked, import the private key to
// a CryptoKey object, read the selected file, produce a
// signature, and put the base 64 encoded signature into the
// appropriate box.
function signFile() {
	// Replace this alert with the correct code
	alert("Clicked the Sign button.");
}

// When the Verify button is clicked, import the public key to
// a CryptoKey object, read the selected file, get the signature
// from the base 64 encoded string in the signature box, and
// then verify the signature. Use an alert to tell whether it's
// a good signature or not.
function verifySignature() {
	// Replace this alert with the correct code
	alert("Clicked the Verify button.");
}


// Hints:
//
// - Key formats:
//   - raw for secret keys
//   - spki for public keys in ArrayBuffers
//   - pkcs8 for private keys in ArrayBuffers
//   - jwk for any keys (JSON)
//
// - Algorithm identifiers
//   - name: RSASSA-PKCS1-v1_5
//   - modulusLength: 2048
//   - publicExponent: new Uint8Array([1,0,1])
//   - hash: SHA-256
