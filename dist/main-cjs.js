'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var NodeRsa = _interopDefault(require('node-rsa'));
var CryptoJS = _interopDefault(require('crypto-js'));

var methods = ['md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160']; // 获取公钥和私钥

function getRsaKey() {
  var size = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 512;
  var crypt = new NodeRsa({
    b: size
  });
  return {
    publicKey: crypt.exportKey('public'),
    privateKey: crypt.exportKey('private')
  };
} // 使用公钥加密

function encryptRsa(publicKey, word) {
  var encrypt = new NodeRsa(publicKey);
  return encrypt.encrypt(word, 'base64');
} // 使用私钥解密

function decryptRsa(privateKey, word) {
  var decrypt = new NodeRsa(privateKey);
  return decrypt.decrypt(word, 'utf8');
} // 使用私钥加密

function encryptRsaByPrivateKey(privateKey, word) {
  var decrypt = new NodeRsa(privateKey);
  return decrypt.encryptPrivate(word, 'base64');
} // 使用公钥解密

function decryptRsaByPublicKey(publicKey, word) {
  var encrypt = new NodeRsa(publicKey);
  return encrypt.decryptPublic(word, 'utf8');
} // 使用私钥加签

function sign(privateKey, word) {
  var method = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'sha256';

  if (!methods.includes(method)) {
    return new Error("method must be one of ".concat(methods.join(',')));
  }

  var encrypt = new NodeRsa(privateKey);
  encrypt.setOptions({
    signingScheme: method
  });
  var encoding = 'base64';
  var sourceEncoding = 'utf8';
  return encrypt.sign(word, encoding, sourceEncoding);
} // 使用公钥验签

function verify(publicKey, word, signature) {
  var method = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 'sha256';

  if (!methods.includes(method)) {
    return new Error("method must be one of ".concat(methods.join(',')));
  }

  var decrypt = new NodeRsa(publicKey);
  decrypt.setOptions({
    signingScheme: method
  });
  var encoding = 'base64';
  var sourceEncoding = 'utf8';
  return decrypt.verify(word, signature, sourceEncoding, encoding);
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
  sign: sign,
  verify: verify,
  decryptRsaByPublicKey: decryptRsaByPublicKey,
  encryptRsaByPrivateKey: encryptRsaByPrivateKey,
  encryptAes: encryptAes,
  decryptAes: decryptAes
};

exports.decryptAes = decryptAes;
exports.decryptRsa = decryptRsa;
exports.decryptRsaByPublicKey = decryptRsaByPublicKey;
exports.default = indexNode;
exports.encryptAes = encryptAes;
exports.encryptRsa = encryptRsa;
exports.encryptRsaByPrivateKey = encryptRsaByPrivateKey;
exports.getRsaKey = getRsaKey;
exports.sign = sign;
exports.verify = verify;
