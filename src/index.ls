/**
 * @package Detox crypto
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
if typeof exports == 'object'
	randombytes	= require('crypto').randomBytes
else
	randombytes	= (size) ->
		array = new Uint8Array(size)
		crypto.getRandomValues(array)
		array

const TWO_WAY_NOISE_PROTOCOL_NAME	= 'Noise_NK_25519_ChaChaPoly_BLAKE2b'
const ONE_WAY_NOISE_PROTOCOL_NAME	= 'Noise_N_25519_ChaChaPoly_BLAKE2b'
const HANDSHAKE_MESSAGE_LENGTH	= 48

/**
 * Increment nonce from `nonce` argument in place
 *
 * @param {!Uint8Array} nonce
 */
!function increment_nonce (nonce)
	for , index in nonce by -1
		++nonce[index]
		if nonce[index] != 0
			break


function Crypto (supercop, ed25519-to-x25519, aez, noise-c, jsSHA)
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
	 * @param {!Uint8Array} data
	 * @param {!Uint8Array} public_key Ed25519 public key
	 * @param {!Uint8Array} private_key Ed25519 private key
	 *
	 * @return {!Uint8Array}
	 */
	function sign (data, public_key, private_key)
		supercop['sign'](data, public_key, private_key)
	/**
	 * @param {!Uint8Array} signature
	 * @param {!Uint8Array} data
	 * @param {!Uint8Array} public_key Ed25519 public key
	 *
	 * @return {boolean}
	 */
	function verify (signature, data, public_key)
		supercop['verify'](signature, data, public_key)
	/**
	 * @constructor
	 *
	 * @param {Uint8Array} key Empty when initialized by initiator and specified on responder side
	 *
	 * @return {!Rewrapper}
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
	Object.defineProperty(Rewrapper::, 'constructor', {value: Rewrapper})
	/**
	 * @constructor
	 *
	 * @param {boolean} initiator
	 * @param {!Uint8Array} key Responder's public X25519 key if `initiator` is `true` or responder's private X25519 key if `initiator` is `false`
	 *
	 * @return {!Encryptor}
	 *
	 * @throws {Error}
	 */
	!function Encryptor (initiator, key)
		if !(@ instanceof Encryptor)
			return new Encryptor(initiator, key)
		if initiator
			@_handshake_state	= noise-c['HandshakeState'](TWO_WAY_NOISE_PROTOCOL_NAME, noise-c['constants']['NOISE_ROLE_INITIATOR'])
			@_handshake_state['Initialize'](null, null, key)
		else
			@_handshake_state	= noise-c['HandshakeState'](TWO_WAY_NOISE_PROTOCOL_NAME, noise-c['constants']['NOISE_ROLE_RESPONDER'])
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
		_handshake_common : !->
			action	= @_handshake_state['GetAction']()
			if action == noise-c['constants']['NOISE_ACTION_SPLIT']
				[@_send_cipher_state, @_receive_cipher_state] = @_handshake_state['Split']()
				# MAC length is 16 and we need 48 bytes key for rewrapper, let's just encrypt corresponding number of zeroes and use it as a key
				# This way we don't need to send any data to get the same set of keys on both sides
				ad						= new Uint8Array(0)
				plaintext				= new Uint8Array(48 - 16)
				@_rewrapper_send_key	= @_send_cipher_state['EncryptWithAd'](ad, plaintext)
				@_rewrapper_receive_key	= @_receive_cipher_state['EncryptWithAd'](ad, plaintext)
				delete @_handshake_state
			else if action == noise-c['constants']['NOISE_ACTION_FAILED']
				delete @_handshake_state
				throw new Error('Noise handshake failed')
		/**
		 * @return {!Array<Uint8Array>} Array `[send_key, receive_key]`, both keys 48 bytes
		 */
		'get_rewrapper_keys' : ->
			[@_rewrapper_send_key, @_rewrapper_receive_key]
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
		'destroy' : !->
			if @_handshake_state
				@_handshake_state['free']()
			if @_send_cipher_state
				@_send_cipher_state['free']()
			if @_receive_cipher_state
				@_receive_cipher_state['free']()
	Object.defineProperty(Encryptor::, 'constructor', {value: Encryptor})
	/**
	 * @param {!Uint8Array} public_key	Responder's public X25519 key
	 * @param {!Uint8Array} plaintext
	 *
	 * @return {!Uint8Array}
	 *
	 * @throws {Error}
	 */
	function one_way_encrypt (public_key, plaintext)
		handshake_state								= noise-c['HandshakeState'](ONE_WAY_NOISE_PROTOCOL_NAME, noise-c['constants']['NOISE_ROLE_INITIATOR'])
		handshake_state['Initialize'](null, null, public_key)
		handshake_message							= handshake_state['WriteMessage']()
		[send_cipher_state, receive_cipher_state]	= handshake_state['Split']()
		ciphertext									= send_cipher_state['EncryptWithAd'](new Uint8Array(0), plaintext)
		send_cipher_state['free']()
		receive_cipher_state['free']()
		new Uint8Array(HANDSHAKE_MESSAGE_LENGTH + ciphertext.length)
			..set(handshake_message)
			..set(ciphertext, HANDSHAKE_MESSAGE_LENGTH)
	/**
	 * @param {!Uint8Array} private_key	Responder's private X25519 key
	 * @param {!Uint8Array} message
	 *
	 * @return {!Uint8Array}
	 *
	 * @throws {Error}
	 */
	function one_way_decrypt (private_key, message)
		handshake_message							= message.subarray(0, HANDSHAKE_MESSAGE_LENGTH)
		ciphertext									= message.subarray(HANDSHAKE_MESSAGE_LENGTH)
		handshake_state								= noise-c['HandshakeState'](ONE_WAY_NOISE_PROTOCOL_NAME, noise-c['constants']['NOISE_ROLE_RESPONDER'])
		handshake_state['Initialize'](null, private_key)
		handshake_state['ReadMessage'](handshake_message)
		[send_cipher_state, receive_cipher_state]	= handshake_state['Split']()
		plaintext									= receive_cipher_state['DecryptWithAd'](new Uint8Array(0), ciphertext)
		send_cipher_state['free']()
		receive_cipher_state['free']()
		plaintext
	/**
	 * @param {!Uint8Array} data
	 *
	 * @return {!Uint8Array}
	 */
	function sha3_256 (data)
		shaObj	= new jsSHA('SHA3-256', 'ARRAYBUFFER') # TODO: Switch to Uint8Array once https://github.com/Caligatio/jsSHA/issues/71 is implemented
		shaObj['update'](data) # TODO: Strictly speaking not correct, but works because of implementation details of jsSHA
		new Uint8Array(shaObj['getHash']('ARRAYBUFFER'))

	{
		'ready'					: (callback) !->
			wait_for	= 4
			!function ready
				--wait_for
				if !wait_for
					callback()
			supercop['ready'](ready)
			ed25519-to-x25519['ready'](ready)
			aez['ready'](ready)
			noise-c['ready'](ready)
		'create_keypair'		: create_keypair
		'convert_public_key'	: convert_public_key
		'sign'					: sign
		'verify'				: verify
		'Rewrapper'				: Rewrapper
		'Encryptor'				: Encryptor
		'one_way_encrypt'		: one_way_encrypt
		'one_way_decrypt'		: one_way_decrypt
		'sha3_256'				: sha3_256
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['supercop.wasm', 'ed25519-to-x25519.wasm', 'aez.wasm', 'noise-c.wasm', 'jssha/src/sha3'], Crypto)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Crypto(require('supercop.wasm'), require('ed25519-to-x25519.wasm'), require('aez.wasm'), require('noise-c.wasm'), require('jssha/src/sha3'))
else
	# Browser globals
	@'detox_crypto' = Crypto(@'supercop_wasm', @'ed25519_to_x25519_wasm', @'aez_wasm', @'noise_c_wasm', @'jsSHA')
