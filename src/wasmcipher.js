// WASM encryption decryption api
const WACrypto = require('./glue');

function AESGCMEncrypt(iv, ad, entityKey, text) {
    return text;
}

function AESGCMDecrypt(iv, ad, key, text) {
    return text;
}

module.exports = {
    encrypt: AESGCMEncrypt,
    decrypt: WACrypto.AESGCMDecrypt
}