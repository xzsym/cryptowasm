const Convenience = require('./convenience');
const WASMCipher = require('./wasmcipher');
// Load the wasm module


export function decrypt(key, content) {
	return WASMCipher.decrypt(key, content);
}

export function encrypt(obj) {
	return Convenience.encrypt(obj);
}

