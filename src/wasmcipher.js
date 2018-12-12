// WASM encryption decryption api
const WACrypto = require('./glue');

function AESGCMEncrypt(iv, ad, entityKey, text) {
    return text;
}

module.exports = {
    encrypt: AESGCMEncrypt,
    AESGCMDecrypt: WACrypto.AESGCMDecrypt
}