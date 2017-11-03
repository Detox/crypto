/**
 * @package   Detox crypto
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
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
	# TODO: wrapping/unwrapping
	# TODO: end-to-end encryption
	{
		'ready'				: Promise.all([supercop.ready]).then(->)
		'generate_keypair'	: generate_keypair
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
