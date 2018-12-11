export default async function() {
	const { add } = await import("./add.wasm");
	const { factorial } = await import("./factorial.wasm");
	const { fibonacci } =  await import("./fibonacci.wasm");
	return { add, factorial, fibonacci };
}