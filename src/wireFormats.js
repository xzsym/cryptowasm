var Utils = require('./utils'),
    h2b = Utils.hex2bits;

module.exports = {
    WIRE_FORMAT_1: h2b('01'),
    WIRE_FORMAT_2: h2b('02'),
    WIRE_FORMAT_3: h2b('03')
};
