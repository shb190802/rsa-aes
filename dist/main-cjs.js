'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var JSEncrypt = _interopDefault(require('node-jsencrypt'));
var CryptoJS = _interopDefault(require('crypto-js'));

function getRsaKey() {
  var crypt = new JSEncrypt({
    default_key_size: 512
  }).getKey();
  return {
    publicKey: crypt.getPublicBaseKeyB64(),
    privateKey: crypt.getPrivateBaseKeyB64()
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
var indexNode = {
  getRsaKey: getRsaKey,
  encryptRsa: encryptRsa,
  decryptRsa: decryptRsa,
  encryptAes: encryptAes,
  decryptAes: decryptAes
};

exports.decryptAes = decryptAes;
exports.decryptRsa = decryptRsa;
exports.default = indexNode;
exports.encryptAes = encryptAes;
exports.encryptRsa = encryptRsa;
exports.getRsaKey = getRsaKey;
