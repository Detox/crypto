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

const NOISE_PROTOCOL_NAME = 'Noise_IK_25519_ChaChaPoly_BLAKE2b'

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


function Crypto (supercop, ed2curve, aez, noise-c)
	/**
	 * @param {Uint8Array} seed Random seed will be generated if `null`
	 *
	 * @return {!Object} Object with keys `public` and `private` that contain `Uint8Array` with public and private keys respectively
	 */
	create_keypairs	= (seed = null) ->
		if !seed
			seed	= supercop.createSeed()
		keys	= supercop.createKeyPair(seed)
		{
			'seed'		: seed
			'ed25519'	:
				'public'	: keys.publicKey
				'private'	: keys.secretKey
			'x25519'	:
				'public'	: ed2curve.convertPublicKey(keys.publicKey)
				'private'	: ed2curve.convertSecretKey(keys.secretKey)
		}
	/**
	 * @param {!Uint8Array} public_key Ed25519 public key
	 *
	 * @return {Uint8Array} X25519 public key (or `null` if `public_key` was invalid)
	 */
	convert_public_key = (public_key) ->
		ed2curve.convertPublicKey(keys.publicKey)
	/**
	 * @constructor
	 *
	 * @param {Uint8Array} key Empty when initialized by initiator and specified on responder side
	 *
	 * @return {Rewrapper}
	 */
	function Rewrapper (key = null)
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
		'wrap' : (data) ->
			increment_nonce(@_nonce)
			# No need to catch exception since we will always have correct inputs
			aez.encrypt(plaintext, new Uint8Array, @_nonce, @_key, 0)
		/**
		 * @param {!Uint8Array} ciphertext
		 *
		 * @return {!Uint8Array} Plaintext
		 */
		'unwrap' : (ciphertext) ->
			increment_nonce(@_nonce)
			# No need to catch exception since we don't have ciphertext expansion
			aez.decrypt(ciphertext, new Uint8Array, @_nonce, @_key, 0)
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
	function Encryptor (initiator, key)
		if !(@ instanceof Encryptor)
			return new Encryptor(initiator, key)
		if initiator
			@_handshake_state	= noise-c.HandshakeState(NOISE_PROTOCOL_NAME, noise-c.constants.NOISE_ROLE_INITIATOR)
			@_handshake_state.Initialize(null, null, key)
		else
			@_handshake_state	= noise-c.HandshakeState(NOISE_PROTOCOL_NAME, noise-c.constants.NOISE_ROLE_RESPONDER)
			@_handshake_state.Initialize(null, key)
	Rewrapper::	=
		/**
		 * @return {Uint8Array} Handshake message that should be sent to the other side or `null` otherwise
		 *
		 * @throws {Error}
		 */
		'get_handshake_message' : ->
			message	= null
			if !@_send_cipher_state
				if @_handshake_state.GetAction() == noise-c.constants.NOISE_ACTION_WRITE_MESSAGE
					message	= @_handshake_state.WriteMessage()
				if @_handshake_state.GetAction() == noise-c.constants.NOISE_ACTION_SPLIT
					[@_send_cipher_state, @_receive_cipher_state] = @_handshake_state.Split()
				else if @_handshake_state.GetAction() == noise-c.constants.NOISE_ACTION_FAILED
					throw new Error('Noise handshake failed')
			message
		/**
		 * @param {!Uint8Array} message Handshake message received from the other side
		 *
		 * @throws {Error}
		 */
		'put_handshake_message' : (message) !->
			if !@_send_cipher_state
				if @_handshake_state.GetAction() == noise-c.constants.NOISE_ACTION_READ_MESSAGE
					@_handshake_state.ReadMessage(message)
				if @_handshake_state.GetAction() == noise-c.constants.NOISE_ACTION_SPLIT
					[@_send_cipher_state, @_receive_cipher_state] = @_handshake_state.Split()
				else if @_handshake_state.GetAction() == noise-c.constants.NOISE_ACTION_FAILED
					throw new Error('Noise handshake failed')
		/**
		 * @param {!Uint8Array} plaintext
		 *
		 * @return {!Uint8Array}
		 *
		 * @throws {Error}
		 */
		'encrypt' : (plaintext) ->
			@_send_cipher_state.EncryptWithAd(new Uint8Array(0), plaintext)
		/**
		 * @param {!Uint8Array} ciphertext
		 *
		 * @return {!Uint8Array}
		 *
		 * @throws {Error}
		 */
		'decrypt' : (ciphertext) ->
			@_receive_cipher_state.DecryptWithAd(new Uint8Array(0), ciphertext)
	Object.defineProperty(Encryptor::, 'constructor', {enumerable: false, value: Encryptor})
	{
		'ready'					: Promise.all([supercop.ready, aez.ready, noise-c.ready]).then(->)
		'create_keypairs'		: create_keypairs
		'convert_public_key'	: convert_public_key
		'Rewrapper'				: Rewrapper
		'Encryptor'				: Encryptor
	}

if typeof define == 'function' && define.amd
	# AMD
	# TODO: ed2curve-js doesn't actually work yet until https://github.com/dchest/ed2curve-js/issues/3 is resolved
	define(['supercop.wasm', 'ed2curve-js', 'aez.wasm', 'noise-c.wasm'], Crypto)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Crypto(require('supercop.wasm'), require('ed2curve-js'), require('aez.wasm'), require('noise-c.wasm'))
else
	# Browser globals
	@'async_eventer' = Crypto(@'supercop_wasm', @'ed2curve', @'aez_wasm', @'noise_c_wasm')
