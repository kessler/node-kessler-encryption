const test = require('ava')
const encryption = require('./index.js')
const crypto = require('crypto')

let data, iv, key, hmacKey

test('encrypt uses aes-256-ctr method, an encryption key, initialization vector (iv) and an hmac key', (t) => {
	const result = encryption.encrypt(data, { key, iv, hmacKey })
	const cipher = crypto.createCipheriv('aes-256-ctr', key, iv.slice(0, 16))
	const expectedEncryptedData = Buffer.concat([cipher.update(data), cipher.final()])
	const expectedHmac = crypto.createHmac('sha256', hmacKey).update(expectedEncryptedData).digest()
	t.deepEqual(result.data, expectedEncryptedData)
	t.deepEqual(result.hmac, expectedHmac)
})

test('encrypt calculates hmac only if hmac key is provided', (t) => {
	const result = encryption.encrypt(data, { key, iv })
	t.is(result.hmac, undefined)
})

test('decrypt data', (t) => {
	const encrypted = encryption.encrypt(data, { key, iv, hmacKey })

	const result = encryption.decrypt(encrypted.data, { key, iv, hmacKey })

	t.deepEqual(result.data, new Buffer(data))
	t.deepEqual(result.hmac, encrypted.hmac)
})

test('decrypt calculates hmac only if hmac key is provided', (t) => {
	const encrypted = encryption.encrypt(data,{ key, iv })
	const result = encryption.decrypt(encrypted.data, { key, iv })
	t.is(result.hmac, undefined)
})

test.beforeEach(() => {
	data = 'secret'
	key = encryption.createEncryptionKey('secretPass', 'salt123')
	iv = new Buffer('9819u2nh2jksnbcjkbcsjksbcsscbskj')
	hmacKey = encryption.createRandomBytes()
})
