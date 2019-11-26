# @kessler/encryption

personal encryption utils

## Example

```js
const { encrypt, decrypt, createEncryptionKey, createRandomBytes } = require('@kessler/encryption')

let key = createEncryptionKey('secretpass', 'salt123')
let iv = new Buffer('9819u2nh2jksnbcjkbcsjksbcsscbskj')
let hmacKey = createRandomBytes()

let encryptedData = encrypt('kljiasojiojioqwennm,nmz,xcnm,zxcnkjlk', key, iv, hmacKey)
let decryptedData = decrypt(encryptedData.data, key, iv, hmacKey)
```
