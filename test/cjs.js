const crypt = require('../dist/main-cjs')

let keys = crypt.getRsaKey()
let secretKey = '1234567890abcdef'

let rasEncrypt = crypt.encryptRsa(keys.publicKey,secretKey)
console.log('rasEncrypt',rasEncrypt)
let rasDecrypt = crypt.decryptRsa(keys.privateKey,rasEncrypt)
console.log('rasDecrypt',rasDecrypt)
let aesEncrypt = crypt.encryptAes(secretKey,'aa12345')
console.log('aesEncrypt',aesEncrypt)
let aesDecrypt = crypt.decryptAes(secretKey,aesEncrypt)
console.log('aesDecrypt',aesDecrypt)