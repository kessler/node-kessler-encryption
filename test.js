const test = require('ava')
const {
	aes256gcm,
	aes256ctr,
	createEncryptionKey,
	createRandomBytes
} = require('./index.js')

const crypto = require('crypto')

let data, iv, key, hmacKey

test('aes256ctr encrypt data using an encryption key, initialization vector (iv) and an hmac key', t => {
	const result = aes256ctr.encrypt(data, { key, iv, hmacKey })
	const cipher = crypto.createCipheriv('aes-256-ctr', key, iv.slice(0, 16))
	const expectedEncryptedData = Buffer.concat([cipher.update(data), cipher.final()])
	const expectedHmac = crypto.createHmac('sha256', hmacKey).update(expectedEncryptedData).digest()
	t.deepEqual(result.data, expectedEncryptedData)
	t.deepEqual(result.hmac, expectedHmac)
})

test('aes256ctr encrypt calculates hmac only if hmac key is provided', t => {
	const result = aes256ctr.encrypt(data, { key, iv })
	t.is(result.hmac, undefined)
})

test('aes256ctr decrypt data', t => {
	const encrypted = aes256ctr.encrypt(data, { key, iv, hmacKey })

	const result = aes256ctr.decrypt(encrypted.data, { key, iv, hmacKey })

	t.deepEqual(result.data, new Buffer(data))
	t.deepEqual(result.hmac, encrypted.hmac)
})

test('aes256ctr decrypt calculates hmac only if hmac key is provided', t => {
	const encrypted = aes256ctr.encrypt(data, { key, iv })
	const result = aes256ctr.decrypt(encrypted.data, { key, iv })
	t.is(result.hmac, undefined)
})

test('aes256gcm encrypts data using an encryption key and optionally, an initialization vector (iv)', t => {
	const encrypted = aes256gcm.encrypt(data, { key })
	const cipher = crypto.createCipheriv('aes-256-gcm', key, encrypted.iv)
	const expectedEncryptedData = Buffer.concat([cipher.update(data), cipher.final()])
	t.deepEqual(encrypted.data, expectedEncryptedData)
	t.deepEqual(encrypted.authTag, cipher.getAuthTag())
})

test('aes256gcm decrypts data', t => {
	const encrypted = aes256gcm.encrypt(data, { key })
	const result = aes256gcm.decrypt(encrypted.data, { key, iv: encrypted.iv, authTag: encrypted.authTag })
	t.is(result.data.toString(), data)
})

test.beforeEach(() => {
	data = 'secret'
	key = createEncryptionKey('secretPass', 'salt123')
	iv = new Buffer('9819u2nh2jksnbcjkbcsjksbcsscbskj')
	hmacKey = createRandomBytes()
})