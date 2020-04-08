import NodeRsa from 'node-rsa'
import CryptoJS from 'crypto-js'

const methods = ['md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160']
// 获取公钥和私钥
export function getRsaKey (size = 512) {
  let crypt = new NodeRsa({ b: size })
  return {
    publicKey: crypt.exportKey('public'),
    privateKey: crypt.exportKey('private')
  }
}
// 使用公钥加密
export function encryptRsa (publicKey, word) {
  let encrypt = new NodeRsa(publicKey)
  return encrypt.encrypt(word, 'base64')
}
// 使用私钥解密
export function decryptRsa (privateKey, word) {
  let decrypt = new NodeRsa(privateKey)
  return decrypt.decrypt(word, 'utf8')
}
// 使用私钥加密
export function encryptRsaByPrivateKey (privateKey, word) {
  let decrypt = new NodeRsa(privateKey)
  return decrypt.encryptPrivate(word, 'base64')
}
// 使用公钥解密
export function decryptRsaByPublicKey (publicKey, word) {
  let encrypt = new NodeRsa(publicKey)
  return encrypt.decryptPublic(word, 'utf8')
}
// 使用私钥加签
export function sign (privateKey, word, method = 'sha256') {
  if (!methods.includes(method)) {
    return new Error(`method must be one of ${methods.join(',')}`)
  }
  let encrypt = new NodeRsa(privateKey)
  encrypt.setOptions({
    signingScheme: method
  })
  let encoding = 'base64'
  let sourceEncoding = 'utf8'
  return encrypt.sign(word, encoding, sourceEncoding)
}
// 使用公钥验签
export function verify (publicKey, word, signature, method = 'sha256') {
  if (!methods.includes(method)) {
    return new Error(`method must be one of ${methods.join(',')}`)
  }
  let decrypt = new NodeRsa(publicKey)
  decrypt.setOptions({
    signingScheme: method
  })
  let encoding = 'base64'
  let sourceEncoding = 'utf8'
  return decrypt.verify(word, signature, sourceEncoding, encoding)
}
// 使用aes秘钥加密
export function encryptAes (secretKey, word) {
  secretKey = CryptoJS.enc.Utf8.parse(secretKey)
  word = CryptoJS.enc.Utf8.parse(word)
  let encrypted = CryptoJS.AES.encrypt(word, secretKey, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  })
  return encrypted.toString()
}
// 使用aes秘钥解密
export function decryptAes (secretKey, word) {
  secretKey = CryptoJS.enc.Utf8.parse(secretKey)
  let decrypted = CryptoJS.AES.decrypt(word, secretKey, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  })
  return CryptoJS.enc.Utf8.stringify(decrypted).toString()
}

export default {
  getRsaKey,
  encryptRsa,
  decryptRsa,
  sign,
  verify,
  decryptRsaByPublicKey,
  encryptRsaByPrivateKey,
  encryptAes,
  decryptAes
}