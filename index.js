const crypto = require('crypto')

module.exports = {
	encrypt,
	decrypt,
	createEncryptionKey,
	createRandomBytes
}

function encrypt(data, { key, iv, hmacKey }) {

	const cipher = crypto.createCipheriv('aes-256-ctr', key, iv.slice(0, 16))
	const encrypted = Buffer.concat([cipher.update(data), cipher.final()])

	let hmac

	if (hmacKey) {
		hmac = crypto.createHmac('sha256', hmacKey).update(encrypted).digest()
	}

	return {
		data: encrypted,
		hmac: hmac
	}
}

function decrypt(data, { key, iv, hmacKey }) {

	const decipherer = crypto.createDecipheriv('aes-256-ctr', key, iv.slice(0, 16))

	let hmac

	if (hmacKey) {
		hmac = crypto.createHmac('sha256', hmacKey).update(data).digest()
	}

	return {
		data: decipherer.update(data),
		hmac: hmac
	}
}

function createEncryptionKey(key, salt) {
	return crypto.pbkdf2Sync(key, salt, 4096, 32, 'sha256')
}

function createRandomBytes(size) {
	if (size === undefined) size = 16
	return crypto.randomBytes(size)
}
