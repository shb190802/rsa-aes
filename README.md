### rsa-aes

针对前后端交互数据加密封装的rsa+aes的库
支持commonjs和es module

* 前端使用crypto-js + jsencrypt
* node端使用crypto-js+node-rsa

包含9个常用方法:

* **getRsaKey(获取公钥私钥)**

* **encryptRsa(rsa公钥加密)**

* **decryptRsa(rsa私钥解密)**

* **sign(rsa私钥加签)**

* **verify(rsa公钥验签)**

* **encryptRsaByPrivateKey(rsa私钥加密)**

* **decryptRsaByPublicKey(rsa公钥解密)(由于jsencrypt不支持，所以客户端无此方法)**

* **encryptAes(aes秘钥加密)**

* **decryptAes(aes秘钥解密)**


**示例：**
```javascript
const crypt = require('rsa-aes')
/**
 * import crypt from 'rsa-aes'
 */
// 获取公钥私钥
let key = crypto.getRsaKey()
let secretKey = '1234567890abcdef'

console.log(key.publicKey)
console.log(key.privateKey)
// rsa公钥加密
let encryptRsa = crypto.encryptRsa(key.publicKey, secretKey)
console.log('encryptRsa', encryptRsa)
// rsa私钥解密
let decryptRsa = crypto.decryptRsa(key.privateKey, encryptRsa)
console.log('decryptRsa', decryptRsa)
// rsa 私钥加密
let encryptRsaByPrivateKey = crypto.encryptRsaByPrivateKey(key.privateKey, decryptRsa)
console.log('encryptRsaByPrivateKey', encryptRsaByPrivateKey)
// rsa 公钥解密  node端支持 客户端不支持
let decryptRsaByPublicKey = crypto.decryptRsaByPublicKey(key.publicKey, encryptRsaByPrivateKey)
console.log('decryptRsaByPublicKey', decryptRsaByPublicKey)
// rsa 私钥加签
let sign = crypto.sign(key.privateKey, secretKey, 'sha1') // ['md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160']
console.log('sign', sign)
// rsa 公钥验签
let verify = crypto.verify(key.publicKey, secretKey, sign, 'sha1')
console.log('verify', verify)
// 使用aes秘钥加密
let aesEncrypt = crypto.encryptAes(secretKey, "aa12345");
console.log("aesEncrypt", aesEncrypt);
// 使用aes秘钥解密
let aesDecrypt = crypto.decryptAes(secretKey, aesEncrypt);
console.log("aesDecrypt", aesDecrypt);
```