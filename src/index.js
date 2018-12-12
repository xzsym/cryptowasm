export async function getMath() {
	const { add } = await import("./add");
	const { factorial } = await import("./factorial");
	const { fibonacci } =  await import("./fibonacci");
	return { add, factorial, fibonacci };
}

export function getEmpty() {
	return { empty: '' };
}

export default getMath;

// module.exports = {
// 	getMath,
// 	getEmpty
// };