const Convenience = require('./convenience');

export function decrypt(key, content) {
	return Convenience.decrypt(key, content);
}

export function encrypt(obj) {
	return Convenience.encrypt(obj);
}

