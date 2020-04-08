import JSEncrypt from 'jsencrypt';
import CryptoJS from 'crypto-js';

var methods = ['md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160']; // 获取公钥和私钥

function getRsaKey() {
  var size = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 512;
  var crypt = new JSEncrypt({
    default_key_size: size
  }).getKey();
  return {
    publicKeyBase64: crypt.getPublicBaseKeyB64(),
    privateKeyBase64: crypt.getPrivateBaseKeyB64(),
    publicKey: crypt.getPublicKey(),
    privateKey: crypt.getPrivateKey()
  };
} // 使用公钥加密

function encryptRsa(publicKey, word) {
  var encrypt = new JSEncrypt();
  encrypt.setPublicKey(publicKey);
  return encrypt.encrypt(word);
} // 使用私钥解密

function decryptRsa(privateKey, word) {
  var decrypt = new JSEncrypt();
  decrypt.setPrivateKey(privateKey);
  return decrypt.decrypt(word);
} // 使用私钥加密

function encryptRsaByPrivateKey(privateKey, word) {
  var decrypt = new JSEncrypt();
  decrypt.setPrivateKey(privateKey);
  return decrypt.encrypt(word);
} // 使用公钥解密 jsencrypt不支持，此方法

function decryptRsaByPublicKey(publicKey, word) {
  var encrypt = new JSEncrypt();
  encrypt.setPublicKey(publicKey);
  return encrypt.decrypt(word);
} // 使用私钥加签

function sign(privateKey, word) {
  var method = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'sha256';

  if (!methods.includes(method)) {
    return new Error("method must be one of ".concat(methods.join(',')));
  }

  var encrypt = new JSEncrypt();
  encrypt.setPrivateKey(privateKey);
  console.log(encrypt);
  return encrypt.sign(word, CryptoJS[method.toUpperCase()], method);
} // 使用公钥验签

function verify(publicKey, word, signature) {
  var method = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 'sha256';

  if (!methods.includes(method)) {
    return new Error("method must be one of ".concat(methods.join(',')));
  }

  var decrypt = new JSEncrypt();
  decrypt.setPublicKey(publicKey);
  return decrypt.verify(word, signature, CryptoJS[method.toUpperCase()]);
} // 使用aes秘钥加密

function encryptAes(secretKey, word) {
  secretKey = CryptoJS.enc.Utf8.parse(secretKey);
  word = CryptoJS.enc.Utf8.parse(word);
  var encrypted = CryptoJS.AES.encrypt(word, secretKey, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  });
  return encrypted.toString();
} // 使用aes秘钥解密

function decryptAes(secretKey, word) {
  secretKey = CryptoJS.enc.Utf8.parse(secretKey);
  var decrypted = CryptoJS.AES.decrypt(word, secretKey, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  });
  return CryptoJS.enc.Utf8.stringify(decrypted).toString();
}
var index = {
  getRsaKey: getRsaKey,
  encryptRsa: encryptRsa,
  decryptRsa: decryptRsa,
  sign: sign,
  verify: verify,
  // decryptRsaByPublicKey,
  encryptRsaByPrivateKey: encryptRsaByPrivateKey,
  encryptAes: encryptAes,
  decryptAes: decryptAes
};

export default index;
export { decryptAes, decryptRsa, decryptRsaByPublicKey, encryptAes, encryptRsa, encryptRsaByPrivateKey, getRsaKey, sign, verify };
