import JSEncrypt from 'jsencrypt'
import CryptoJS from 'crypto-js'
// 获取公钥和私钥
export function getRsaKey(){
  let crypt = new JSEncrypt({
    default_key_size: 512
  }).getKey()
  return {
    publicKey: crypt.getPublicBaseKeyB64(),
    privateKey: crypt.getPrivateBaseKeyB64()
  }
}
// 使用公钥加密
export function encryptRsa(publicKey,word){
	let encrypt = new JSEncrypt()
  encrypt.setPublicKey(publicKey)
  return encrypt.encrypt(word)
}
// 使用私钥解密
export function decryptRsa(privateKey,word){
	let decrypt = new JSEncrypt()
  decrypt.setPrivateKey(privateKey)
  return decrypt.decrypt(word)
}
// 使用aes秘钥加密
export function encryptAes(secretKey,word) {
  secretKey = CryptoJS.enc.Utf8.parse(secretKey)
  word = CryptoJS.enc.Utf8.parse(word)
  let encrypted = CryptoJS.AES.encrypt(word,secretKey,{
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  })
  return encrypted.toString()
}
// 使用aes秘钥解密
export function decryptAes(secretKey,word) {
  secretKey = CryptoJS.enc.Utf8.parse(secretKey)
  let decrypted = CryptoJS.AES.decrypt(word,secretKey,{
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  })
  return CryptoJS.enc.Utf8.stringify(decrypted).toString()
}

export default  {
	getRsaKey,
	encryptRsa,
	decryptRsa,
	encryptAes,
	decryptAes
}