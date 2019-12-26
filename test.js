const test = require('ava')
const fs = require('fs')
const path = require('path')
const concatStream = require('concat-stream')
const { Readable } = require('stream')

const {
	aes256gcm,
	aes256ctr,
	createEncryptionKey,
	createRandomBytes
} = require('./index.js')

const crypto = require('crypto')

let data, iv, key, hmacKey, dataStream

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

test.cb('aes256gcm encrypt stream', t => {
	const { iv, stream: encryptStream, authTag } = aes256gcm.encryptStream({ key })
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
	const expectedEncryptedData = Buffer.concat([cipher.update(data), cipher.final()])

	const concat = concatStream(result => {
		t.deepEqual(result, expectedEncryptedData)
		t.deepEqual(authTag(), cipher.getAuthTag())
		t.end()
	})

	dataStream.pipe(encryptStream).pipe(concat)
})

test.cb('aes256gcm decrypt stream', t => {
	const { iv, data: encryptedData, authTag } = aes256gcm.encrypt(data, { key })
	const { stream: decryptStream } = aes256gcm.decryptStream({ key, iv, authTag })
	const concat = concatStream(result => {
		t.is(result.toString(), data)
		t.end()
	})

	new MemoryStream(encryptedData).pipe(decryptStream).pipe(concat)
})

test.beforeEach(() => {
	data = 'secret'
	dataStream = new MemoryStream(data)
	key = createEncryptionKey('secretPass', 'salt123')
	iv = new Buffer('9819u2nh2jksnbcjkbcsjksbcsscbskj')
	hmacKey = createRandomBytes()
})

class MemoryStream extends Readable {
	constructor(data) {
		super()
		this._data = data
	}

	_read(size) {
		this.push(this._data)
		this.push(null)
	}
}