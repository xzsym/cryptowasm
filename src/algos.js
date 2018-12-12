var Forge = require('@symphony/forge');
var Utils = require('./utils');

var Algos = {};

function checkType(type) {
    if (type !== 'AES-GCM' && type !== 'AES-CBC') {
        throw new Error('Unsupported cipher type ' + type + ' specified.');
    }
}

Algos.createCipher = function(type, key) {
    checkType(type);

    return Forge.cipher.createCipher(type, Utils.b642bits(key));
};

Algos.createDecipher = function(type, key) {
    checkType(type);

    return Forge.cipher.createDecipher(type, Utils.b642bits(key));
};

Algos.AESCBCDecrypt = function(iv, key, ciphertext, padFunction) {
    var cipher = Algos.createDecipher('AES-CBC', key),
        ctBytes = Utils.createBuffer(Utils.b642bits(ciphertext));

    cipher.start({
        iv: Utils.b642bits(iv)
    });

    cipher.update(ctBytes);

    var ret;

    if (!cipher.finish(padFunction)) {
        throw new Error('Decryption failed.');
    } else {
        ret = Utils.bits2b64(cipher.output.getBytes());
    }

    return ret;
};
/*
 * @param iv Base64 String - Initialization vector
 * @param adata Base64 String - Additional data
 * @param key Base64 String
 * @param plaintext Base64 String
 * @param tagBefore Boolean - for encryption must correspond to same tagLocation for decryption
 *
 */

Algos.AESGCMEncrypt = function(iv, adata, key, plaintext) {
    var cipher = Algos.createCipher('AES-GCM', key);

    cipher.start({
        iv: Utils.b642bits(iv),
        additionalData: Utils.b642bits(adata)
    });

    cipher.update(Utils.createBuffer(Utils.b642bits(plaintext)));

    var ret;

    if (!cipher.finish()) {
        throw new Error('Encryption failed.');
    } else {

        var concat = cipher.output.getBytes().concat(cipher.mode.tag.getBytes());

        ret = Forge.util.encode64(concat);
    }
    return ret;
};

/*
 * @param iv Base64 String - Initialization vector
 * @param adata Base64 String - Additional data
 * @param key Base64 String
 * @param plaintext Base64 String
 */

Algos.AESGCMDecrypt = function(iv, adata, key, ciphertext) {
    var cipher = Algos.createDecipher('AES-GCM',  key),
        ctBytes = Utils.createBuffer(Utils.b642bits(ciphertext));

    var ct = Utils.createBuffer(ctBytes.getBytes(ctBytes.length() - 16));
    var tag = Utils.createBuffer(ctBytes.getBytes());

    cipher.start({
        iv: Utils.b642bits(iv),
        additionalData: Utils.b642bits(adata),
        tag: tag
    });

    cipher.update(ct);

    var ret;

    if (!cipher.finish()) {
        throw new Error('Decryption failed.');
    } else {
        ret = Utils.bits2b64(cipher.output.getBytes());
    }

    return ret;
};

/**
 * DES-16468 Added the forceUtf8 parameter to force plaintext to be encoded as UTF-8 before
 * PBKDF2 encrypts the plaintext. This solves Security issue from DES-16457 but users that
 * uses special characters that fall outside the Basic Latin character set will lose access
 * to the app, so this will remain optional until solution is implemented. For more information
 * visit Jira Issue DES-16468.
 */

Algos.PBKDF2 = function(salt, iterations, plaintext, forceUtf8) {

    var saltBytes = Forge.util.decode64(salt),
        text = plaintext;

    // If forceUtf8 is true we force UTF8 encode on plaintext before it's consumed by PBKDF2
    if (forceUtf8) {
        text = Forge.util.encodeUtf8(plaintext);
    }
    
    var hashBits = Forge.pkcs5.pbkdf2(text, saltBytes, iterations, 32, Forge.md.sha256.create());

    return Utils.bits2b64(hashBits);
};

Algos.RSAGenerateKeyPair = function(size, callback) {
    size = size || 2048;

    var self = this;

    var opts = {
        bits: size,
        e: 0x10001
    };

    if (callback) {
        var state = Forge.pki.rsa.createKeyPairGenerationState(opts.bits, opts.e);

        var step = function() {
            if (!Forge.pki.rsa.stepKeyPairGenerationState(state, 50)) {
                setTimeout(step, 1);
            } else {
                callback(self._formatPem(state.keys));
            }
        };

        setTimeout(step);
    } else {
        var keyPair = Forge.pki.rsa.generateKeyPair(opts);

        return self._formatPem(keyPair);
    }
};

Algos._formatPem = function(keyPair) {
    var privatePem = Forge.pki.privateKeyToPem(keyPair.privateKey),
        publicPem = Forge.pki.publicKeyToPem(keyPair.publicKey);

    return {
        privateKey: privatePem,
        publicKey: publicPem
    };
};

Algos.RSAEncrypt = function(publicKeyPem, plaintext) {
    var publicKey = Forge.pki.publicKeyFromPem(publicKeyPem),
        ptBytes = Forge.util.decodeUtf8(plaintext),
        ctBytes = publicKey.encrypt(ptBytes);

    return Forge.util.encode64(ctBytes);
};

Algos.RSADecrypt = function(privateKeyPem, ciphertext) {
    var privateKey = Forge.pki.privateKeyFromPem(privateKeyPem),
        ctBytes = Forge.util.decode64(ciphertext),
        ptBytes = privateKey.decrypt(ctBytes);

    return Forge.util.encodeUtf8(ptBytes);
};

Algos.RSASign = function(privateKeyPem, plaintext) {
    var privateKey = Forge.pki.privateKeyFromPem(privateKeyPem),
        md = Forge.md.sha256.create();

    md.update(plaintext, 'utf8');

    var signature = privateKey.sign(md);

    return Utils.bits2b64(signature);
};

Algos.RSAVerify = function(publicKey, signature, plaintext) {
    var publicKeyPem = Forge.pki.publicKeyFromPem(publicKey),
        sigBytes = Forge.util.decode64(signature),
        md = Forge.md.sha256.create();

    md.update(plaintext, 'utf8');

    var ret;

    try {
        ret = publicKeyPem.verify(md.digest().getBytes(), sigBytes);
    } catch(e) {
        ret = false;
    }

    return ret;
};

Algos.SHA256Digest = function(message) {
    var md = Forge.md.sha256.create();
    md.update(message);

    return Utils.bits2b64(md.digest().getBytes());
};

Algos.HmacSha256Digest = function(message,key) {
    //expects key to be bytes
    var hmac = Forge.hmac.create();
    hmac.start('sha256',key);
    hmac.update(message);

    return Utils.bits2b64(hmac.digest().getBytes())
}

if (window.hasOwnProperty('appbridge') && window.appbridge.hasOwnProperty('CryptoLib')) {
    module.exports = window.appbridge.CryptoLib;
    module.exports.AESCBCDecrypt = Algos.AESCBCDecrypt;
    module.exports.SHA256Digest = Algos.SHA256Digest;
    module.exports.createCipher = Algos.createCipher;
    module.exports.createDecipher = Algos.createDecipher;
    module.exports.HmacSha256Digest = Algos.HmacSha256Digest;
} else if ((window.hasOwnProperty('ssf') && window.ssf.CryptoLib)) {
    module.exports = Algos;
    module.exports.AESGCMEncrypt = window.ssf.CryptoLib.AESGCMEncrypt || Algos.AESGCMEncrypt;
    module.exports.AESGCMDecrypt = window.ssf.CryptoLib.AESGCMDecrypt || Algos.AESGCMDecrypt;
    module.exports.RSADecrypt = window.ssf.CryptoLib.RSADecrypt || Algos.RSADecrypt;
} else {
    module.exports = Algos;
}
