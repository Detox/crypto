/**
 * @package   Detox crypto
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
if typeof exports == 'object'
	randombytes	= require('crypto').randomBytes
else
	randombytes	= (size) ->
		array = new Uint8Array(size)
		crypto.getRandomValues(array)
		array

const NOISE_PROTOCOL_NAME = 'Noise_NK_25519_ChaChaPoly_BLAKE2b'

/**
 * Increment nonce from `nonce` argument in place
 *
 * @param {!Uint8Array} nonce
 */
function increment_nonce (nonce)
	for , index in nonce by -1
		++nonce[index]
		if nonce[index] != 0
			break


function Crypto (supercop, ed25519-to-x25519, aez, noise-c)
	/**
	 * @param {Uint8Array} seed Random seed will be generated if `null`
	 *
	 * @return {!Object}
	 */
	function create_keypair (seed = null)
		if !seed
			seed	= supercop['createSeed']()
		keys	= supercop['createKeyPair'](seed)
		# Note: In ed25519 private key is already hashed, while in x25519 we use seed as it is done in libsodium and other libraries (see https://github.com/orlp/ed25519/issues/10)
		{
			'seed'		: seed
			'ed25519'	:
				'public'	: keys['publicKey']
				'private'	: keys['secretKey']
			'x25519'	:
				'public'	: ed25519-to-x25519['convert_public_key'](keys['publicKey'])
				'private'	: ed25519-to-x25519['convert_private_key'](seed)
		}
	/**
	 * @param {!Uint8Array} public_key Ed25519 public key
	 *
	 * @return {Uint8Array} X25519 public key (or `null` if `public_key` was invalid)
	 */
	function convert_public_key (public_key)
		ed25519-to-x25519['convert_public_key'](public_key)
	/**
	 * @constructor
	 *
	 * @param {Uint8Array} key Empty when initialized by initiator and specified on responder side
	 *
	 * @return {Rewrapper}
	 */
	!function Rewrapper (key = null)
		if !(@ instanceof Rewrapper)
			return new Rewrapper(key)
		if key == null
			key	= randombytes(48)
		@_key	= key
		@_nonce	= new Uint8Array(12)
	Rewrapper::	=
		/**
		 * @return {!Uint8Array}
		 */
		'get_key' : ->
			@_key
		/**
		 * @param {!Uint8Array} plaintext
		 *
		 * @return {!Uint8Array} Ciphertext
		 */
		'wrap' : (plaintext) ->
			increment_nonce(@_nonce)
			# No need to catch exception since we will always have correct inputs
			aez['encrypt'](plaintext, new Uint8Array(0), @_nonce, @_key, 0)
		/**
		 * @param {!Uint8Array} ciphertext
		 *
		 * @return {!Uint8Array} Plaintext
		 */
		'unwrap' : (ciphertext) ->
			increment_nonce(@_nonce)
			# No need to catch exception since we don't have ciphertext expansion
			aez['decrypt'](ciphertext, new Uint8Array(0), @_nonce, @_key, 0)
	Object.defineProperty(Rewrapper::, 'constructor', {enumerable: false, value: Rewrapper})
	/**
	 * @constructor
	 *
	 * @param {boolean} initiator
	 * @param {!Uint8Array} key Responder's public X25519 key if `initiator` is `true` or responder's private X25519 key if `initiator` is `false`
	 *
	 * @return {Encryptor}
	 *
	 * @throws {Error}
	 */
	!function Encryptor (initiator, key)
		if !(@ instanceof Encryptor)
			return new Encryptor(initiator, key)
		if initiator
			@_handshake_state	= noise-c['HandshakeState'](NOISE_PROTOCOL_NAME, noise-c['constants']['NOISE_ROLE_INITIATOR'])
			@_handshake_state['Initialize'](null, null, key)
		else
			@_handshake_state	= noise-c['HandshakeState'](NOISE_PROTOCOL_NAME, noise-c['constants']['NOISE_ROLE_RESPONDER'])
			@_handshake_state['Initialize'](null, key)
	Encryptor::	=
		/**
		 * @return {boolean}
		 */
		'ready' : ->
			!@_handshake_state
		/**
		 * @return {Uint8Array} Handshake message that should be sent to the other side or `null` otherwise
		 *
		 * @throws {Error}
		 */
		'get_handshake_message' : ->
			message	= null
			if @_handshake_state
				if @_handshake_state['GetAction']() == noise-c['constants']['NOISE_ACTION_WRITE_MESSAGE']
					message	= @_handshake_state['WriteMessage']()
				@_handshake_common()
			message
		_handshake_common : !->
			if @_handshake_state['GetAction']() == noise-c['constants']['NOISE_ACTION_SPLIT']
				[@_send_cipher_state, @_receive_cipher_state] = @_handshake_state['Split']()
				delete @_handshake_state
			else if @_handshake_state['GetAction']() == noise-c['constants']['NOISE_ACTION_FAILED']
				delete @_handshake_state
				throw new Error('Noise handshake failed')
		/**
		 * @param {!Uint8Array} message Handshake message received from the other side
		 *
		 * @throws {Error}
		 */
		'put_handshake_message' : (message) !->
			if @_handshake_state
				if @_handshake_state['GetAction']() == noise-c['constants']['NOISE_ACTION_READ_MESSAGE']
					@_handshake_state['ReadMessage'](message)
				@_handshake_common()
		/**
		 * @param {!Uint8Array} plaintext
		 *
		 * @return {!Uint8Array}
		 *
		 * @throws {Error}
		 */
		'encrypt' : (plaintext) ->
			@_send_cipher_state['EncryptWithAd'](new Uint8Array(0), plaintext)
		/**
		 * @param {!Uint8Array} ciphertext
		 *
		 * @return {!Uint8Array}
		 *
		 * @throws {Error}
		 */
		'decrypt' : (ciphertext) ->
			@_receive_cipher_state['DecryptWithAd'](new Uint8Array(0), ciphertext)
	Object.defineProperty(Encryptor::, 'constructor', {enumerable: false, value: Encryptor})
	{
		'ready'					: (callback) !->
			Promise.all([supercop['ready'], ed25519-to-x25519['ready'], aez['ready'], noise-c['ready']]).then().then(callback)
		'create_keypair'		: create_keypair
		'convert_public_key'	: convert_public_key
		'Rewrapper'				: Rewrapper
		'Encryptor'				: Encryptor
	}

if typeof define == 'function' && define.amd
	# AMD
	define(['supercop.wasm', 'ed25519-to-x25519.wasm', 'aez.wasm', 'noise-c.wasm'], Crypto)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Crypto(require('supercop.wasm'), require('ed25519-to-x25519.wasm'), require('aez.wasm'), require('noise-c.wasm'))
else
	# Browser globals
	@'async_eventer' = Crypto(@'supercop_wasm', @'ed25519_to_x25519_wasm', @'aez_wasm', @'noise_c_wasm')
