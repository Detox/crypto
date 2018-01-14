# Detox crypto [![Travis CI](https://img.shields.io/travis/Detox/detox-crypto/master.svg?label=Travis%20CI)](https://travis-ci.org/Detox/detox-crypto)
High-level utilities that combine under simple interfaces complexity of the cryptographic layer used in Detox project.

Essentially provides wrapper functions and objects for:
* Ed25519 and X25519 keys creation
* AEZ block cipher
* Noise protocol (Noise_NK_25519_ChaChaPoly_BLAKE2b, Noise_N_25519_ChaChaPoly_BLAKE2b)

## How to install
```
npm install @detox/crypto
```

## How to use
NOTE: In modern versions of Node.js (4.x and higher) `Buffer` inherits `Uint8Array`, so you can pass `Buffer` directly whenever `Uint8Array` is expected.

Node.js:
```javascript
var detox_crypto = require('@detox/crypto')

detox_crypto.ready(function () {
    // Do stuff
});
```
Browser:
```javascript
requirejs(['@detox/crypto'], function (detox_crypto) {
    detox_crypto.ready(function () {
        // Do stuff
    });
})
```

## API
### detox_crypto.ready(callback)
* `callback` - Callback function that is called when library is ready for use

### detox_crypto.create_keypair(seed = null : Uint8Array) : Object
Creates keypairs from specified seed (if not specified, random seed will be generated).

Returns an object with properties:
* `seed` (same as argument or random generate otherwise)
* `ed25519` - Ed25519 keypair
  * `public` - Public key
  * `private` - Private key (already hashed, as used in [orlp/ed25519](https://github.com/orlp/ed25519))
* `x25519` - X25519 keypair
  * `public` - Public key
  * `private` - Private key

### detox_crypto.convert_public_key(ed25519_public_key : Uint8Array) : Uint8Array
Converts Ed25519 public key into X25519/Curve25519 public key. Returns `null` if conversion fails.

### detox_crypto.sign(data : Uint8Array, ed25519_public_key : Uint8Array, ed25519_private_key : Uint8Array) : Uint8Array
Signs data and returns 64 bytes signature.

### detox_crypto.verify(signature : Uint8Array, data : Uint8Array, ed25519_public_key : Uint8Array) : boolean
Verifies that signature corresponds to specified data and public key.

### detox_crypto.Rewrapper(key = null : Uint8Array) : detox_crypto.Rewrapper
Constructor for Rewrapper object. Can be initialized with key (48 bytes, typically done on responder side) or key will be generated automatically (typically done on initiator side).

Uses AEZ block cipher.

### detox_crypto.Rewrapper.get_key() : Uint8Array
Key that was specified during initialization or that was generated automatically.

### detox_crypto.Rewrapper.wrap(plaintext : Uint8Array) : Uint8Array
Wraps plaintext into ciphertext.

### detox_crypto.Rewrapper.unwrap(plaintext : Uint8Array) : Uint8Array
Unwraps plaintext from ciphertext, inverse to `wrap()`.

### detox_crypto.Encryptor(initiator : boolean, key : Uint8Array) : detox_crypto.Encryptor
Constructor for Encryptor object. If initialized for initiator then `key` will be public key (X25519) of the responder. If initialized for responder then `key` will be private key (X25519) of the responder.

Uses Noise protocol (Noise_NK_25519_ChaChaPoly_BLAKE2b).

Constructor and all methods can throw `Error` if something goes wrong, be ready to catch exceptions.

### detox_crypto.Encryptor.ready() : boolean
Quick check if handshake was finished and Encryptor is ready for encryption/decryption.

### detox_crypto.Encryptor.get_handshake_message() : Unt8Array
Get handshake message that should be send to another side.

### detox_crypto.Encryptor.put_handshake_message(message : Unt8Array)
Put handshake message that was received from another side.

### detox_crypto.Encryptor.get_rewrapper_keys() : Array
Get rewrapper keys derived from handshake. 2 elements are `Uint8Array`s of 48 bytes, first one most be used for sending data (wrapping) and second for receiving (unwrapping).

### detox_crypto.Encryptor.encrypt(plaintext : Uint8Array) : Unt8Array
Encrypts plaintext into ciphertext for another side.

### detox_crypto.Encryptor.decrypt(plaintext : Uint8Array) : Unt8Array
Decrypts plaintext from ciphertext from another side.

### detox_crypto.Encryptor.destroy()
Destroys stateful data structures and makes Encryptor unusable.

### detox_crypto.one_way_encrypt(public_key : Uint8Array, plaintext : Uint8Array) : Uint8Array
One-way encryption for specified X25519 public key.

Uses Noise protocol (Noise_N_25519_ChaChaPoly_BLAKE2b).

Returns combined handshake message and ciphertext.

### detox_crypto.one_way_decrypt(private_key : Uint8Array, message : Uint8Array) : Uint8Array
One-way decryption of the message for specified X25519 private key.

Uses Noise protocol (Noise_N_25519_ChaChaPoly_BLAKE2b).

Takes combined handshake message and ciphertext as input message and returns plaintext.

Take a look at `src/index.ls` for JsDoc sections with arguments and return types as well as methods description, look at `tests/index.ls` for usage examples.

## Contribution
Feel free to create issues and send pull requests (for big changes create an issue first and link it from the PR), they are highly appreciated!

When reading LiveScript code make sure to configure 1 tab to be 4 spaces (GitHub uses 8 by default), otherwise code might be hard to read.

## License
Free Public License 1.0.0 / Zero Clause BSD License

https://opensource.org/licenses/FPL-1.0.0

https://tldrlegal.com/license/bsd-0-clause-license
