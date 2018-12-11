export default async function() {
	const { add } = await import("./add");
	const { factorial } = await import("./factorial");
	const { fibonacci } =  await import("./fibonacci");
	return { add, factorial, fibonacci };
}