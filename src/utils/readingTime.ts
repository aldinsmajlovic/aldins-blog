// Rough reading time from raw markdown body. ~200 words/min, floored to 1.
export function readingTime(body: string | undefined): number {
	const words = (body ?? '').trim().split(/\s+/).filter(Boolean).length;
	return Math.max(1, Math.round(words / 200));
}
