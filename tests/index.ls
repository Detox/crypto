/**
 * @package Detox crypto
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
lib			= require('..')
test		= require('tape')

seed			= Buffer.from('9fc9b77445f8b077c29fe27fc581c52beb668ecd25f5bb2ba5777dee2a411e97', 'hex')
ed25519_public	= Buffer.from('8fbe438aab6c40dc2ebc839ba27530ca1bf23d4efd36958a3365406efe52ccd1', 'hex')
ed25519_private	= Buffer.from('28e9e1d48cb0e52e437080e4a180058d7a42a07abcd05ea2ec4e6122cded8f6a0d2a6b9fd1878fd76ab20caecab666916ac3cc772fc57f8fa6e8dc3227bb8497', 'hex')
x25519_public	= Buffer.from('26100e941bdd2103038d8dec9a1884694736f591ee814e66ae6e2e2284757136', 'hex')
x25519_private	= Buffer.from('28e9e1d48cb0e52e437080e4a180058d7a42a07abcd05ea2ec4e6122cded8f6a', 'hex')
signature		= Buffer.from('20f9031704a64240ccf8d5fa8964ecec10ed6b00ea60559c4d7e92ee7ef7e330376d0ca48a23119258c3b9ea2d4df5514e4e52653b02159c110b4f1ded3dfd00', 'hex')

key					= Buffer.from('4f99a089d76256347358580797cf4242bd3afc1b3e62f39a76ca066b64fae8346a9dbfc9e8e1c59506ee919954324f58', 'hex')
plaintext			= 'Hello, Detox!'
known_ciphertext	= Buffer.from('b6a8f817b079a5af10c3434a1d', 'hex')

known_hash			= Buffer.from('3c90fb006657254ec5b6db421018f96c41a01cc73b3563b7b710f5ab0cfb1629', 'hex')

<-! lib.ready
test('Keypair generation', (t) !->
	t.plan(9)

	keypair			= lib.create_keypair(seed)

	t.equal(keypair.seed.join(','), seed.join(','), 'Seed is kept the same')
	t.equal(keypair.ed25519.public.join(','), ed25519_public.join(','), 'Generated correct ed25519 public key')
	t.equal(keypair.ed25519.private.join(','), ed25519_private.join(','), 'Generated correct ed25519 private key')
	t.equal(keypair.x25519.public.join(','), x25519_public.join(','), 'Generated correct x25519 public key')
	t.equal(keypair.x25519.private.join(','), x25519_private.join(','), 'Generated correct x25519 private key')

	t.equal(lib.sign(Buffer.from(plaintext), ed25519_public, ed25519_private).join(','), signature.join(','), 'Correct signature')

	t.ok(lib.verify(signature, Buffer.from(plaintext), ed25519_public), 'Correct verification')

	t.notOk(lib.verify(ed25519_private, Buffer.from(plaintext), ed25519_public), 'Correct verification failure')

	t.equal(lib.convert_public_key(keypair.ed25519.public).join(','), x25519_public.join(','), 'Ed25519 public key converted to X25519 correctly')
)

test('Rewrapping', (t) !->
	t.plan(7)

	instance	= lib.Rewrapper()

	t.ok(instance.get_key() instanceof Uint8Array, 'Key was generated automatically')
	t.equal(instance.get_key().length, 48, 'Key has correct length')

	wrapper				= lib.Rewrapper(key)
	unwrapper			= lib.Rewrapper(key)

	t.equal(wrapper._nonce.join(','), (new Uint8Array(12)).join(','), 'Nonce defaults to zeroes')

	ciphertext	= wrapper.wrap(Buffer.from(plaintext))
	t.equal(wrapper._nonce[wrapper._nonce.length - 1], 1, 'Nonce was incremented')
	t.equal(ciphertext.join(','), known_ciphertext.join(','), 'Wrapped correctly')

	plaintext_decrypted	= unwrapper.unwrap(ciphertext)
	t.equal(wrapper._nonce[wrapper._nonce.length - 1], 1, 'Nonce was incremented')
	t.equal(Buffer.from(plaintext_decrypted).toString(), plaintext, 'Unwrapped correctly')
)

test('Encryption', (t) !->
	t.plan(8)

	initiator	= lib.Encryptor(true, x25519_public)
	responder	= lib.Encryptor(false, x25519_private)

	message	= initiator.get_handshake_message()
	t.equal(message.length, 48, 'Message size is correct')

	responder.put_handshake_message(message)
	message	= responder.get_handshake_message()
	t.equal(message.length, 48, 'Message size is correct')

	initiator.put_handshake_message(message)

	t.equal(initiator.get_rewrapper_keys()[0].length, 48, 'Rewrapper keys are correct #1')
	t.equal(initiator.get_rewrapper_keys()[1].length, 48, 'Rewrapper keys are correct #2')

	t.equal(initiator.get_rewrapper_keys()[0].toString(), responder.get_rewrapper_keys()[1].toString(), 'Rewrapper keys are the same #1')
	t.equal(initiator.get_rewrapper_keys()[1].toString(), responder.get_rewrapper_keys()[0].toString(), 'Rewrapper keys are the same #2')

	ciphertext			= initiator.encrypt(Buffer.from(plaintext))
	plaintext_decrypted	= responder.decrypt(ciphertext)
	t.equal(Buffer.from(plaintext_decrypted).toString(), plaintext, 'Plaintext decrypted correctly')

	ciphertext			= responder.encrypt(Buffer.from(plaintext))
	plaintext_decrypted	= initiator.decrypt(ciphertext)
	t.equal(Buffer.from(plaintext_decrypted).toString(), plaintext, 'Plaintext decrypted correctly')

	initiator.destroy()
	responder.destroy()
)

test('One-way encryption', (t) !->
	t.plan(2)

	ciphertext	= lib.one_way_encrypt(x25519_public, Buffer.from(plaintext))

	t.equal(ciphertext.length, 48 + Buffer.from(plaintext).length + 16, 'Ciphertext length is correct')

	plaintext_decrypted	= lib.one_way_decrypt(x25519_private, ciphertext)
	t.equal(Buffer.from(plaintext_decrypted).toString(), plaintext, 'Plaintext decrypted correctly')
)

test('Blake2b-256', (t) !->
	t.plan(1)

	t.equal(lib.blake2b_256(seed).join(','), known_hash.join(','), 'Blake2b-256 hash computed correctly')
)
