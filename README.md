# @kessler/encryption

personal encryption utils

## Example

```js
const encryption = require('@kessler/encryption')

let key = encryption.createEncryptionKey('secretpass', 'salt123')
let iv = new Buffer('9819u2nh2jksnbcjkbcsjksbcsscbskj')
let hmacKey = encryption.createRandomBytes()

let encryptedData = encryption.encrypt('kljiasojiojioqwennm,nmz,xcnm,zxcnkjlk', key, iv, hmacKey)
let decryptedData = encryption.decrypt(encryptedData.data, key, iv, hmacKey)
```