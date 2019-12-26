const crypto = require('crypto')

module.exports = {
	aes256ctr: {
		encrypt: encryptAes256Ctr,
		decrypt: decryptAes256Ctr
	},
	aes256gcm: {
		encrypt: encryptAes256Gcm,
		decrypt: decryptAes256Gcm
	},
	createEncryptionKey,
	createRandomBytes
}

function encryptAes256Gcm(data, { key, iv = Buffer.from(crypto.randomBytes(16)) }) {
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
	return {
		iv,
		data: Buffer.concat([cipher.update(data), cipher.final()]),
		authTag: cipher.getAuthTag()
	}
}

function decryptAes256Gcm(data, { key, iv, authTag }) {
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
	decipher.setAuthTag(authTag)
	return {
		data: Buffer.concat([decipher.update(data), decipher.final()])
	}
}

function encryptAes256Ctr(data, { key, iv, hmacKey }) {

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

function decryptAes256Ctr(data, { key, iv, hmacKey }) {

	const decipherer = crypto.createDecipheriv('aes-256-ctr', key, iv.slice(0, 16))

	let hmac

	if (hmacKey) {
		hmac = crypto.createHmac('sha256', hmacKey).update(data).digest()
	}

	return {
		data: Buffer.concat([decipherer.update(data), decipherer.final()]),
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