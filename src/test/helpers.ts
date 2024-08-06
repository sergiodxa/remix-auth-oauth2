function isResponse(value: unknown): value is Response {
	return value instanceof Response;
}

export async function catchResponse(promise: Promise<unknown>) {
	try {
		await promise;
		throw new Error("Should have failed.");
	} catch (error) {
		if (isResponse(error)) return error;
		throw error;
	}
}
