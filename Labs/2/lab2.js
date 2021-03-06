// Cryptographic functionality for lab 2


// When the Encrypt button is clicked, derive a 256-bit AES-CBC
// key from the entered pass phrase, then read the selected file
// using FileReader.readAsArrayBuffer. On completed read, encrypt
// the file using the key, build a Blob out of the IV plus the
// resulting ciphertext, then change the window.location to a
// URL representing the Blob.
function encryptFile() {
    // First, we need to make a CryptoKey from the pass phrase
    var passphrase = document.getElementById("passphrase").value;

    convertPassphraseToKey(passphrase
    ).then(function(aesKey) {
        var file = document.getElementById("datafile").files[0];
        var reader = new FileReader;

        reader.onload = function() {
            var ivBytes = window.crypto.getRandomValues(new Uint8Array(16));
            var plaintextBytes = new Uint8Array(reader.result);

            window.crypto.subtle.encrypt(
                {name: "AES-CBC", iv: ivBytes}, aesKey, plaintextBytes
            ).then(function(ciphertextBuffer) {
                // Build a Blob with the 16-byte IV followed by the ciphertext
                var blob = new Blob(
                    [ivBytes, new Uint8Array(ciphertextBuffer)],
                    {type: "application/octet-stream"}
                );
                var blobUrl = URL.createObjectURL(blob);

                window.location = blobUrl;
            }).catch(function(err) {
                alert("Could not encrypt the plaintext: " + err.message);
            });
        }

        // Kick off the file read
        reader.readAsArrayBuffer(file);
    });
}

// When the Decrypt button is clicked, derive a 256-bit AES-CBC
// key from the entered pass phrase, then read the selected file
// using FileReader.readAsArrayBuffer. On completed read, decrypt
// the file using the key and the IV in its first 16 bytes. Finally,
// build a Blob out of the resulting plaintext, then change the
// window.location to a URL representing the Blob.
function decryptFile() {
    // Nearly identical to encrypt operation
    var passphrase = document.getElementById("passphrase").value;

    convertPassphraseToKey(passphrase
    ).then(function(aesKey) {
        var file = document.getElementById("datafile").files[0];
        var reader = new FileReader;

        reader.onload = function() {
            // The IV is the first 16 bytes of the result, the
            // ciphertext is the rest
            var ivBytes = new Uint8Array(reader.result.slice(0, 16));
            var ciphertextBytes = new Uint8Array(reader.result.slice(16));

            window.crypto.subtle.decrypt(
                {name: "AES-CBC", iv: ivBytes}, aesKey, ciphertextBytes
            ).then(function(plaintextBuffer) {
                var blob = new Blob(
                    [new Uint8Array(plaintextBuffer)],
                    {type: "application/octet-stream"}
                );
                var blobUrl = URL.createObjectURL(blob);

                window.location = blobUrl;
            }).catch(function(err) {
                alert("Could not decrypt the ciphertext: " + err.message);
            });
        }

        reader.readAsArrayBuffer(file);
    });
}


// convertPassphraseToKey is asynchronous because it uses
// Web Cryptography API methods that are asynchronous. So
// we will return a Promise, rather than take a callback.
// The Promise yields a 256-bit AES-CBC CryptoKey.
function convertPassphraseToKey(passphraseString) {
    var iterations = 1000000;   // Longer is slower... hence stronger
    var saltString = "You need to know the salt later to decrypt. It's not a secret, though.";
    var saltBytes = stringToByteArray(saltString);
    var passphraseBytes = stringToByteArray(passphraseString);

    // deriveKey needs to be given a base key. This is just a
    // CryptoKey that represents the starting passphrase.
    return window.crypto.subtle.importKey(
        "raw", passphraseBytes, {name: "PBKDF2"}, false, ["deriveKey"]
    ).then(function(baseKey) {
        return window.crypto.subtle.deriveKey(
            // Firefox currently only supports SHA-1 with PBKDF2
            {name: "PBKDF2", salt: saltBytes, iterations: iterations, hash: "SHA-1"},
            baseKey,
            {name: "AES-CBC", length: 256}, // Resulting key type we want
            false,  // Can't see any need to ever export this
            ["encrypt", "decrypt"]
        );
    }).catch(function(err) {
        alert("Could not generate a key from passphrase '" + passphrase + "': " + err.message);
    });
}

// Hints:
//
// SubtleCrypto methods:
//
// window.crypto.subtle.deriveKey(derivationAlgorithm, baseKey, targetAlgorithm, exportable, usages)
//  - returns a Promise that yields the CryptoKey created
//  - derivationAlgorithm is the algorithm used for the derivation, with properties
//    - name is PBKDF2
//    - salt is an ArrayBuffer with a known value
//    - iterations is an integer telling how many rounds to perform
//    - hash is the hash function used by the derivation algorith, SHA-1 here
//  - baseKey is a CryptoKey representing the password
//  - targetAlgorithm is what the resulting key will be used for
//    - name is AES-CBC, length is 256
//  - extractable is a boolean.
//  - usages is ["encrypt", "decrypt"]
//
// window.crypto.subtle.importKey(keyFormat, keyBytes, algorithm, exportable, usages)
// - returns a Promise yielding the CryptoKey
// - keyFormat, algorithm, exportable, usages same as in above methods
// - keyBytes is an ArrayBuffer or byte array with key value
//
// window.crypto.subtle.encrypt(algorithm, key, plaintext)
// - returns a Promise yielding an ArrayBuffer containing the ciphertext
// - algorithm object has name and iv properties
//   - name same as used for generateKey and importKey
//   - iv is 16 bytes of random data, needed to maintain security
//   - iv is not secret
// - plaintext is an ArrayBuffer or byte array
//
// window.crypto.subtle.decrypt(algorithm, key, ciphertext)
// - returns a Promise yielding an ArrayBuffer containing the plaintext
// - algorithm object has name and iv properties
//   - name same as used for generateKey and importKey
//   - iv must be the same 16 bytes used when encrypting
// - ciphertext is an ArrayBuffer or byte array

//
// Read the selected file using FileReader.readAsArrayBuffer:
//
//    var file = document.getElementById("datafile").files[0];
//    var reader = new FileReader();
//    reader.onload = function() {
//        handle the result, an ArrayBuffer named reader.result
//    }
//    reader.readAsArrayBuffer(file);
//
// Return the contents of an ArrayBuffer using a Blob:
//
//    var blob = new Blob([listOfBuffersOrViews], {type: "application/octet-stream"});
//    var url = URL.createObjectURL(blob);
//    window.location = url;
