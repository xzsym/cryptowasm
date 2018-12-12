var Forge = require('@symphony/forge');

var Utils = {};

Utils.str2bits = function(str) {
    return Forge.util.createBuffer(str, 'utf8').getBytes();
};

Utils.bits2str = function(bits) {
    return Forge.util.decodeUtf8(bits);
};

Utils.str2b64 = function(str) {
    return Utils.bits2b64(Utils.str2bits(str));
};

Utils.b642bits = function(b64) {
    return Forge.util.decode64(b64);
};

Utils.bits2b64 = function(bits) {
    return Forge.util.encode64(bits);
};

Utils.b642str = function(b64) {
    return Forge.util.decodeUtf8(Utils.b642bits(b64));
};

Utils.b642hex = function(b64) {
    return Forge.util.bytesToHex(Utils.b642bits(b64));
};

Utils.bits2Number = function(bits) {
    return parseInt(Utils.b642hex(Utils.bits2b64(bits)), 16);
};

Utils.hex2b64 = function(hex) {
    return Utils.bits2b64(Utils.hex2bits(hex));
};

Utils.hex2bits = function(hex) {
    return Forge.util.hexToBytes(hex);
};

Utils.createBuffer = function(bits) {
    return Forge.util.createBuffer(bits);
};

Utils.components2b64 = function(components) {
    var buf = Utils.createBuffer();

    for (var i = 0; i < components.length; i++) {
        var component = components[i];

        buf.putBytes(component);
    }

    return Utils.bits2b64(buf.getBytes());
};

Utils.createBytePadding = function(size) {
    var buffer = Forge.util.createBuffer();
    for (var i = 0;i < size;i++) {
        buffer.putByte(0);
    }
    return buffer.getBytes();
};

module.exports = Utils;
