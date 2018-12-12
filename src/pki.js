var Forge = require('@symphony/forge'),
    PKI = {};

/**
 * Creates a certificate signing request.
 *
 * @param {Object} keyPair
 * @param {String} keyPair.publicKey - A public key in PEM format.
 * @param {String} keyPair.privateKey - A private key in PEM format.
 * @returns {String} The CSR in PEM format.
 */
PKI.createCsr = function(keyPair) {
    if (!keyPair.publicKey) {
        throw new Error('A public key is required to create a CSR.');
    }

    if (!keyPair.privateKey) {
        throw new Error('A private key is required to create a CSR.');
    }

    var csr = Forge.pki.createCertificationRequest();
    csr.publicKey = Forge.pki.publicKeyFromPem(keyPair.publicKey);
    csr.setSubject([
        {
            name: 'commonName',
            value: 'symphony.com'
        }, {
            name: 'countryName',
            value: 'US'
        }, {
            shortName: 'ST',
            value: 'CA'
        }, {
            name: 'localityName',
            value: 'Palo Alto'
        }, {
            name: 'organizationName',
            value: 'Symphony'
        }
    ]);
    csr.sign(Forge.pki.privateKeyFromPem(keyPair.privateKey));

    return Forge.pki.certificationRequestToPem(csr);
};

module.exports = PKI;
