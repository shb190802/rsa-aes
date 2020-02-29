### rsa-aes

针对前后端交互数据加密封装的ras+aes的库
支持commonjs和es module

* 前端使用crypto-js + jsencrypt
* node端使用crypto-js+node-jsencrypt

包含5个常用方法:

* **getRsaKey(获取公钥私钥)**

* **encryptRsa(rsa公钥加密)**

* **decryptRsa(rsa公钥解密)**

* **encryptAes(aes秘钥加密)**

* **decryptAes(aes秘钥解密)**


**示例：**
```javascript
const crypt = require('ras-aes')
/**
 * import crypt from 'rsa-aes'
 */
// 获取公钥私钥
let keys = crypt.getRsaKey()
let secretKey = '1234567890abcdef'

// 使用rsa公钥加密
let rasEncrypt = crypt.encryptRsa(keys.publicKey,secretKey)
console.log('rasEncrypt',rasEncrypt)
// 使用rsa公钥解密
let rasDecrypt = crypt.decryptRsa(keys.privateKey,rasEncrypt)
console.log('rasDecrypt',rasDecrypt)
// 使用aes秘钥加密
let aesEncrypt = crypt.encryptAes(secretKey,'aa12345')
console.log('aesEncrypt',aesEncrypt)
// 使用aes秘钥解密
let aesDecrypt = crypt.decryptAes(secretKey,aesEncrypt)
console.log('aesDecrypt',aesDecrypt)

```