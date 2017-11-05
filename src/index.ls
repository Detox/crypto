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


function Crypto (supercop, aez, noise-c)
	/**
	 * @return {!Object} Object with keys `public` and `private` that contain `Uint8Array` with public and private keys respectively
	 */
	generate_keypair	= ->
		keys	= supercop.createKeyPair(supercop.createSeed())
		{
			'public'	: keys.publicKey
			'private'	: keys.secretKey
		}
	/**
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
	# TODO: end-to-end encryption
	{
		'ready'				: Promise.all([supercop.ready, aez.ready, noise-c.ready]).then(->)
		'generate_keypair'	: generate_keypair
		'Rewrapper'			: Rewrapper
	}

if typeof define == 'function' && define.amd
	# AMD
	define(['supercop.wasm', 'aez.wasm', 'noise-c.wasm'], Crypto)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Crypto(require('supercop.wasm'), require('aez.wasm'), require('noise-c.wasm'))
else
	# Browser globals
	@'async_eventer' = Crypto(@'supercop_wasm', @'aez_wasm', @'noise_c_wasm')
