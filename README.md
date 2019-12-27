# @kessler/encryption

personal encryption utils

## Example

```js
const { encrypt, decrypt, createEncryptionKey, createRandomBytes } = require('@kessler/encryption')

const key = createEncryptionKey('secretpass', 'salt123')
const iv = new Buffer('9819u2nh2jksnbcjkbcsjksbcsscbskj')
const hmacKey = createRandomBytes()

const encryptedData = encrypt('kljiasojiojioqwennm,nmz,xcnm,zxcnkjlk', { key, iv, hmacKey })
const decryptedData = decrypt(encryptedData.data, { key, iv, hmacKey })
```
