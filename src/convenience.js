var Forge = require('@symphony/forge'),
      Algos = require('./algos'),
      WireFormats = require('./wireFormats'),
      WASMCipher = require('./wasmcipher'),
      Utils = require('./utils');

var usedRandoms = {},
    Convenience = {};

var b2b64 = Utils.bits2b64,
      s2b64 = Utils.str2b64,
      b642b = Utils.b642bits,
      b642s = Utils.b642str,
      s2b = Utils.str2bits,
      h2b = Utils.hex2bits,
      b642hex = Utils.b642hex,
      createBuffer = Utils.createBuffer,
      c2b64 = Utils.components2b64,
      b2n = Utils.bits2Number;

var USE_PASSWORD_TRUE = h2b('01'),
      USE_PASSWORD_FALSE = h2b('00');

var CHUNK_SIZE = 8182;

var TOKEN_POINTS = [ 3, 5, 8, 13 ];

var TAG_SIZE = 16;

var TOKEN_SIZE = 12;

Convenience.tokenizeEntityV2 = function(entityKey, entityText) {
    var lowercaseEntity = entityText.toLowerCase();
    var fullToken = b642b(Algos.HmacSha256Digest(s2b(lowercaseEntity), b642b(entityKey)));
    var tokenBuffer = createBuffer(fullToken);

    //return the first 12 bytes of the full token.
    return tokenBuffer.getBytes(TOKEN_SIZE);
};


//version [1 byte] | rotationId [8 bytes] | tokens [each token 12 bytes, max 4 tokens]

Convenience.tokenizeEntitiesV2 = function(entityKey, entityText) {
    var version = h2b('02');
    var rotationId = Utils.createBytePadding(8);

    var components = [ version, rotationId ];

    for (var i = 0;i < TOKEN_POINTS.length;i++) {
        var tokenPoint = TOKEN_POINTS[ i ];

        var numberOfCharacters = entityText.length;
        if (numberOfCharacters >= tokenPoint) {
            var token = Convenience.tokenizeEntityV2(entityKey, entityText.substring(0, tokenPoint));
            components.push(token);
        }
    }

    return '!' + c2b64(components);
};

/*
 * @param entityKey
 * @param entityText
 * @Algorithm
        byte[] hmacKey = SHA256(<entitykey>);
        byte[] iv32 = HMAC-SHA256(<hmacKey>, <lowercased plaintext in bytes> );
        return first 16 bytes of iv32.
*/

Convenience.generateEntityIV = function(entityKey, entityText) {
    var hmacKey = b642b(Algos.SHA256Digest(b642b(entityKey)));
    var iv32 = Algos.HmacSha256Digest(s2b(entityText.toLowerCase()), hmacKey);
    return createBuffer(b642b(iv32)).getBytes(16);
};

/*
    EntityCiphertextTransportV2
    version [1 byte] | rotationId [8 bytes] | tokens [each token 12 bytes, max 4 tokens] | iv [16 bytes] | tag [16 bytes] | ciphertext [variable size] | token number [1 byte]

        version will be hardcoded as  (byte) 2.
        rotationId will be hardcoded as (long) 0.
        tokens - max 4. Tokenized with entityKey
        iv -
            byte[] hmacKey = SHA256(<entitykey>);
            byte[] iv32 = HMAC-SHA256(<hmacKey>, <lowercased plaintext in bytes> );
            return first 16 bytes of iv32.

        tag, AES GCM encryption tag which is generated during the encryption.
        ciphertext, variable size based on the length of the hashtag
        tokennumber, number of tokens generated. It can have values {0,1,2,3,4}. It is in byte format.

        The entity ciphertext transport string will be produced as following:
        "!" + Base64Encode(<entity ciphertext transport shown above>)

*/

Convenience.encryptEntityV2 = function(entityKey, entityText) {
    var version = h2b('02');
    var rotationId = Utils.createBytePadding(8);
    entityText = entityText.toLowerCase();

    var tokens = [];

    for (var i = 0;i < TOKEN_POINTS.length;i++) {
        var tokenPoint = TOKEN_POINTS[ i ];

        var numberOfCharacters = entityText.length;
        if (numberOfCharacters >= tokenPoint) {
            var token = Convenience.tokenizeEntityV2(entityKey, entityText.substring(0, tokenPoint));
            tokens.push(token);
        }
    }

    var iv = Convenience.generateEntityIV(entityKey, entityText);
    var ad = Utils.createBytePadding(16);

    //ct is automatically prefixed with tag
    var ct = b642b(Algos.AESGCMEncrypt(b2b64(iv), b2b64(ad), entityKey, s2b64(entityText)));

    var CTbuffer = createBuffer(ct);
    var CTSize = CTbuffer.length() - TAG_SIZE;
    var rawCT = CTbuffer.getBytes(CTSize);
    var tag = CTbuffer.getBytes();

    var tokenNumber = s2b(tokens.length);
    var components = Array.prototype.concat(version, rotationId, tokens, iv, tag, rawCT, h2b(String(tokenNumber)));

    return '!' + c2b64(components);
};

Convenience.decryptEntityV2 = function(entityKey, ct) {
    var buffer = createBuffer(b642b(ct));
    var version = b2n(buffer.getBytes(1));
    var rotationId = b2n(buffer.getBytes(8));

    /*
     * Need to go to end of buffer to extract number of tokens before
     * we can extract the tokens themselves. We can't extract the tokens
     * if we do not know how many to extract. Store the remaining ct in a temp bufer
     * to go last byte of buffer which represents the number of tokens.
     * Once we have the numberOfTokens, use it to start where we left off
     */
    var tempBuffer = buffer.getBytes(buffer.length() - 1);

    var numberOfTokens = b2n(buffer.getBytes(1));

    buffer = createBuffer(tempBuffer);

    var tokens = buffer.getBytes( numberOfTokens * TOKEN_SIZE );
    var iv = buffer.getBytes(16);
    var tag = buffer.getBytes(16);
    var ct = buffer.getBytes();
    var ad = Utils.createBytePadding(16);

    var ctBytes = createBuffer(ct).putBytes(tag).getBytes()

    return b642s(Algos.AESGCMDecrypt(b2b64(iv), b2b64(ad), entityKey, b2b64(ctBytes)));
};

Convenience.encrypt = function(opts) {
    var key = opts.key,
        usePassword = opts.usePassword,
        plaintext = opts.plaintext,
        iv = opts.ivBytes || Convenience.randomBytes(16),
        ad = opts.adBytes || Convenience.randomBytes(16),
        salt;

    if (usePassword) {
        salt = Convenience.randomBytes(16);
        key = Algos.PBKDF2(b2b64(salt), 10000, key);
    }

    try {
        var ct = b642b(WASMCipher.AESGCMEncrypt(b2b64(iv), b2b64(ad), key, s2b64(plaintext)));
    } catch (e) {
        return false;
    }

    var components = Convenience.formatCiphertextForWire({
        iv: iv,
        ct: ct,
        ad: ad,
        key: key,
        salt: salt,
        podId: opts.podId,
        version: opts.version,
        usePassword: usePassword,
        rotationId: opts.rotationId
    });

    return c2b64(components);
};

Convenience.decrypt = function(key, ciphertext) {
    var ctData = Convenience.extractCiphertextData(ciphertext);

    if (!ctData) {
        return false;
    }

    if (ctData.version === WireFormats.WIRE_FORMAT_1 && ctData.usePassword) {
        key = Algos.PBKDF2(b2b64(ctData.salt), 10000, key);
    }

    try {
        var mode = ctData.mode;
        var pt;

        //Tag not include with ciphertext in cbc mode
        if (typeof mode === 'number' && mode === 1) {
            pt = Algos.AESCBCDecrypt(b2b64(ctData.iv), key, b2b64(ctData.ct), function() { return true; });
        } else {
            pt = WASMCipher.AESGCMDecrypt(b2b64(ctData.iv), b2b64(ctData.ad), key, b2b64(ctData.ct));
        }
    } catch(e) {
        return false;
    }

    try {
        return b642s(pt);
    } catch(e) {
        return pt;
    }
};

Convenience.randomBytes = function(n) {
    var i = 0,
        data;

    var generate = function() {
        var bytes = Forge.random.getBytesSync(n);

        data = {
            bytes: bytes,
            b64: b2b64(bytes)
        };
    };

    generate();

    while (usedRandoms[data.b64]) {
        if (i === 2) {
            throw new Error('The same random data has been generated three times. Something ' +
                'is extremely wrong.');
        }

        generate();
        i++;
    }

    usedRandoms[data.b64] = true;

    return data.bytes;
};

Convenience.extractCiphertextData = function(ciphertext) {
    var ctBuffer = createBuffer(b642b(ciphertext)),
        version = createBuffer(ctBuffer.getBytes(1)).toHex(),
        ret;

    switch(version) {
        case '01':
            ret = Convenience.extractWireFormat1CiphertextData(ctBuffer);
            break;
        case '02':
            ret = Convenience.extractWireFormat2CiphertextData(ctBuffer);
            break;
        case '03':
            ret = Convenience.extractWireFormat3CiphertextData(ctBuffer);
            break;
        default:
            ret = false;
            break;
    }

    return ret;
};

Convenience.formatCiphertextForWire = function(opts) {
    var version = opts.version || WireFormats.WIRE_FORMAT_3;

    if (!opts.iv || !opts.ad || !opts.ct) {
        throw new Error('An IV, authentication data, and some ciphertext are required.');
    }

    var ret;

    //returns array of components
    switch(version) {
        case WireFormats.WIRE_FORMAT_1:
            ret = formatWireFormat1(opts);
            break;
        case WireFormats.WIRE_FORMAT_2:
            ret = formatWireFormat2(opts);
            break;
        case WireFormats.WIRE_FORMAT_3:
            ret = formatWireFormat3(opts);
            break;
        default:
            throw new Error('Unsupported wire format.');
    }

    return ret;
};

Convenience.extractWireFormat1CiphertextData = function(buf) {
    var usePassword = createBuffer(buf.getBytes(1)).toHex() === '01';

    return {
        version: WireFormats.WIRE_FORMAT_1,
        usePassword: usePassword,
        salt: usePassword ? buf.getBytes(16) : [],
        iv: buf.getBytes(16),
        ad: buf.getBytes(16),
        ct: buf.getBytes()
    };
};

Convenience.extractWireFormat2CiphertextData = function(buf) {
    return {
        version: WireFormats.WIRE_FORMAT_2,
        podId: parseInt(createBuffer(buf.getBytes(4)).toHex(), 16),
        rotationId: (buf.getBytes(8), 0),
        iv: buf.getBytes(16),
        ad: buf.getBytes(16),
        ct: buf.getBytes()
    };
};

Convenience.extractCiphertextMetaData = function(ciphertext) {
    var ret = Convenience.extractCiphertextData(ciphertext);

    return {
        version: b2n(ret.version),
        podId: ret.podId,
        rotationId: ret.rotationId
    };
};


Convenience.performFileDecryption = function(data, next, key, skipChunking) {
    var buffer = createBuffer(data.response);

    var version = parseInt(createBuffer(buffer.getBytes(1)).toHex(), 16);
    var parts;

    if (version === 3) {
        parts = Convenience.extractWireFormat3CiphertextData(buffer);
    } else {
        parts = Convenience.extractWireFormat2CiphertextData(buffer);
    }


    var tmpBuf = createBuffer(parts.ct),
        ctBuf = createBuffer(tmpBuf.getBytes(tmpBuf.length() - 16)),
        tag = createBuffer(tmpBuf.getBytes()),
        decipher = Algos.createDecipher('AES-GCM', key),
        totalChunks = Math.ceil(ctBuf.length() / CHUNK_SIZE),
        chunkNumber = 1;

    decipher.start({
        iv: parts.iv,
        additionalData: parts.ad,
        tag: tag
    });

    if (skipChunking) {
        var allChunks = ctBuf.getBytes(ctBuf.length());
        decipher.update(createBuffer(allChunks));
        complete();
        return;
    }

    function complete() {
        if (!decipher.finish()) {
            var err = new Error('Failed to decrypt file.');

            next(err);
            return;
        }

        var binary = decipher.output.getBytes(),
            arrayBuf = new ArrayBuffer(binary.length),
            bufView = new Uint8Array(arrayBuf);

        for (var i = 0; i < binary.length; i++) {
            bufView[i] = binary.charCodeAt(i);
        }

        data.response = arrayBuf;

        next(data);
    }

    function readChunk(chunkNumber, currentChunk) {
        if (global.DEBUG) {
            console.log('Decrypting chunk ' + chunkNumber + ' of ' + totalChunks + '.');
        }

        decipher.update(createBuffer(currentChunk));

        if (chunkNumber !== totalChunks) {
            return;
        }

        complete();
    }

    while (ctBuf.length() > 0) {
        _.defer(readChunk.bind(null, chunkNumber, ctBuf.getBytes(CHUNK_SIZE)));
        chunkNumber++;
    }
};

Convenience.performFileEncryption = function(data, next, key, reader, rotationId, version) {

    data.payload.delete('streamId');

    var iv = Convenience.randomBytes(16),
        additionalData = Convenience.randomBytes(16),
        cipher = Algos.createCipher('AES-GCM', key),
        bytes = new Uint8Array(reader.result),
        binary = '';

    /**
     * Encodes an ArrayBuffer as a binary string.
     */
    for (var i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    var buffer = createBuffer(binary);

    if (global.DEBUG) {
        console.log('Read pending file of size ' + buffer.length() + ' bytes.');
    }

    cipher.start({
        iv: iv,
        additionalData: additionalData
    });

    var totalChunks = Math.ceil(buffer.length() / CHUNK_SIZE),
        chunkNumber = 1;

    function didReadChunk(currentChunk) {
        if (currentChunk !== totalChunks) {
            return;
        }

        if (!cipher.finish()) {
            var err = new Error('Failed to encrypt file with name ' + data.payload.name + '.');

            next(err);
            return;
        }

        if (global.DEBUG) {
            console.log('All ' + totalChunks + ' have been encrypted.');
        }

        var formatted = Convenience.formatCiphertextForWire({
            version: version,
            ct: cipher.output.getBytes(),
            podId: global.env.POD_ID,
            rotationId: rotationId,
            ad: additionalData,
            key: key,
            iv: iv
        });

        /**
         * We now have an array of binary strings. To avoid character encoding issues, we
         * need to convert those strings in to one concatenated Uint8Array and create a Blob
         * from it.
         *
         * To do so, we first allocate a new Uint8Array of length ciphertext length + 61. The
         * ciphertext always lives at the last array parameter of formatCiphertextForWire. 61
         * comes from all the fixed length stuff in the ciphertext wire format:
         *
         * 1 (version) + 4 (podId) + 8 (rotationId) + 16 (iv) + 16 (aData) + 16 (tag) = 61
         */

        var cipherTextIndex,
            cipherMetadataSize;

        if (rotationId !== 0) {
            ciphertextIndex = 5;
            cipherMetadataSize = 94;
        } else {
            ciphertextIndex = formatted.length - 1;
            cipherMetadataSize = 61;
        }

        var ctSize = formatted[ ciphertextIndex ].length,
            bytes = new Uint8Array(cipherMetadataSize + ctSize),
            tagBytes = cipher.mode.tag.getBytes(),

             /**
             * Keep track of our position in the overall 'bytes' array.
             *
             * @type {number}
             */
            pos = 0,
            i,j,k,
            part;



        /**
         * Iterate over the array of strings...
         */
        for (i = 0; i < formatted.length; i++) {
            part = formatted[ i ];

            /**
             * ... And put their character codes into the byte array.
             */
            for (j = 0; j < part.length; j++) {
                bytes[ pos ] = part.charCodeAt(j);

                pos++
            }


            /**
            * The authentication tag comes separately from the formatted text, so iterate over its characters
            * last.
            */

            if (i === ciphertextIndex) {
                for (k = 0; k < tagBytes.length; k++) {
                    bytes[ pos ] = tagBytes.charCodeAt(k);
                    pos++;
                }
            }
        }

         /**
         * Mobile expects all images to have a Content-Type in the header of an image format.
         * Doing this allows mobile to display images inline as thumbnails in their messages.
         */

        var name = data.payload.get('name');
        var type = data.payload.get('type');

        if (!(/image/.test(type))) {
            type = 'application/octet-stream';
        }

        var blob = new Blob([ bytes ], { type: type });

        data.payload.delete(name);
        data.payload.delete('name');
        data.payload.delete('type');
        data.payload.delete('data');

        data.payload.set(name, blob, name);

        data.beforeSend = function(xhr) {
            xhr.setRequestHeader('Is-Encrypted', 'true');
        };

        next(data);
    }

    function readChunk(chunkNumber, chunk) {
        if (global.DEBUG) {
            console.log('Encrypting chunk ' + chunkNumber + ' of ' + totalChunks + '.');
        }

        cipher.update(createBuffer(chunk));

        didReadChunk(chunkNumber);
    }

    while (buffer.length() > 0) {
        _.defer(readChunk.bind(null, chunkNumber, buffer.getBytes(CHUNK_SIZE)));
        chunkNumber++;
    }
};

Convenience.extractVersion = function(ciphertext) {
    var ctBuffer = createBuffer(b642b(ciphertext));
    return createBuffer(ctBuffer.getBytes(1)).toHex();
};

Convenience.extractWireFormat3CiphertextData = function(buf) {

    var obj = {
        version: WireFormats.WIRE_FORMAT_3,
        podId: parseInt(createBuffer(buf.getBytes(4)).toHex(), 16),
        rotationId: parseInt(createBuffer(buf.getBytes(8)).toHex(), 16),
        iv: buf.getBytes(16),
        ad: buf.getBytes(16)
    };

    var remainingSize = buf.length();
    var ctSize = remainingSize - 33;

    obj.ct = buf.getBytes(ctSize);

    obj.keyId = b2b64(h2b(createBuffer(buf.getBytes(32)).toHex()));

    //If mode === 1 then use cbc mode instead of gcm mode
    //If is not 0 or 1 then throw error
    obj.mode = parseInt(createBuffer(buf.getBytes(1)).toHex(), 16);

    //We are not suppose to concatenate tag onto ciphertext in CBC mode because there is no concept of tags in CBC mode
    if (obj.mode === 1) {
        var ctBuffer = createBuffer(obj.ct);
        obj.ct = ctBuffer.getBytes(ctBuffer.length() - TAG_SIZE);
    }

    return obj;
};

Convenience.encryptEntity = function(opts) {
    if (typeof opts !== 'object' || typeof opts.plaintext !== 'string' || !opts.key) {
        throw new Error('Plaintext and key are required.');
    }
    opts.plaintext = opts.plaintext;

    opts.ivBytes = getEntityIv(opts.plaintext, opts.key);
    opts.adBytes = Utils.createBytePadding(16);
    opts.version = WireFormats.WIRE_FORMAT_1;

    return '?' + Convenience.encrypt(opts);
};

//https://perzoinc.atlassian.net/wiki/display/CRYPTO/How+to+construct+a+KeyId
Convenience.generateKeyId = function (key) {
    return b642b(Algos.HmacSha256Digest('KeyFingerprint', key));
};

function getEntityIv(plaintext, key) {
    var hashedKeyBytes = b642b(Algos.SHA256Digest(b642b(key)));

    var plaintextBytes = Utils.str2bits(plaintext);
    var ivPreHash = plaintextBytes + hashedKeyBytes;
    var iv32 = b642b(Algos.SHA256Digest(ivPreHash));
    return iv32.substring(0, 16);
}

function formatWireFormat1(opts) {
    var usePassword = opts.usePassword,
        salt = opts.salt || [];

    if (usePassword && !salt.length) {
        throw new Error('A salt is required.');
    }

    return [ WireFormats.WIRE_FORMAT_1, usePassword ? USE_PASSWORD_TRUE : USE_PASSWORD_FALSE, salt, opts.iv, opts.ad,
        opts.ct ];
}

function formatWireFormat2(opts) {
    var podId = padInt32(opts.podId);
    var rotationId = padInt64(0);

    if (!podId) {
        throw new Error('A pod ID is required.');
    }

    return [ WireFormats.WIRE_FORMAT_2, podId, rotationId, opts.iv, opts.ad, opts.ct ];
}

function formatWireFormat3(opts) {
    var podId = padInt32(opts.podId);
    var rotationId = padInt64(opts.rotationId || 0);

    if (!podId || !opts.key) {
        throw new Error('A pod ID and key is required for WireFormatV3: ', opts);
    }

    var keyId = Convenience.generateKeyId(b642b(opts.key));

    var mode = generateMode();

    return [ WireFormats.WIRE_FORMAT_3, podId, rotationId, opts.iv, opts.ad, opts.ct, keyId, mode ];
}

//Default `mode` is a single empty byte
function generateMode() {
    var buf = createBuffer()
    buf.putByte(0);
    return buf.getBytes();
}

// Pad int so it is 64 bits
// Good for ~4 billion key rotations
function padInt64(int) {
    if (int === undefined) {
        return false;
    }

    var buf = createBuffer();
    buf.putInt32(0);
    buf.putInt32(int & 0xffffffff);
    return buf.getBytes();
}


function padInt32(int) {
    if (int === undefined) {
        return false;
    }

    var buf = createBuffer();
    buf.putInt32(int & 0xffffffff);

    return buf.getBytes();
}

module.exports = Convenience;
