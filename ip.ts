/**
 * Pure IP address utilities: validation, normalization, numeric/hex forms.
 * No state, no I/O.
 */

export function isIPv4(ip: string): boolean {
	// Validate IPv4: split and check each octet is 0-255 (no leading zeros,
	// no trailing garbage — part !== String(num) rejects both).
	const parts = ip.split('.');
	if (parts.length !== 4) return false;
	for (const part of parts) {
		const num = Number.parseInt(part, 10);
		if (Number.isNaN(num) || num < 0 || num > 255 || part !== String(num)) return false;
	}
	return true;
}

/**
 * Normalize a trailing IPv4-mapped segment (e.g. ::ffff:1.2.3.4) into two
 * hex groups. Returns null when a mapped suffix is present but invalid.
 */
function normalizeIPv6(ip: string): string | null {
	const mapped = /^(.*:)((?:\d{1,3}\.){3}\d{1,3})$/.exec(ip);
	if (!mapped) return ip;
	if (!isIPv4(mapped[2])) return null;
	const o = mapped[2].split('.').map((p) => Number.parseInt(p, 10));
	const hi = (((o[0] << 8) | o[1]) >>> 0).toString(16);
	const lo = (((o[2] << 8) | o[3]) >>> 0).toString(16);
	return mapped[1] + hi + ':' + lo;
}

export function isIPv6(ip: string): boolean {
	if (!ip.includes(':')) return false;
	if (ip.includes(':::')) return false;
	// Exactly one '::' at most
	if (ip.split('::').length - 1 > 1) return false;
	// A lone leading/trailing ':' (not part of '::') is invalid
	if ((ip.startsWith(':') && !ip.startsWith('::')) || (ip.endsWith(':') && !ip.endsWith('::'))) return false;
	const normalized = normalizeIPv6(ip);
	if (normalized === null) return false;
	const parts = normalized.split(':');
	const hasDoubleColon = normalized.includes('::');
	let groups = 0;
	for (const part of parts) {
		if (part === '') continue; // empty stems from '::'
		if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
		groups++;
	}
	// Without '::' exactly 8 groups are required; with '::' at most 7
	return hasDoubleColon ? groups <= 7 : groups === 8 && parts.length === 8;
}

/**
 * Return the IP if it is a valid IPv4/IPv6 address, otherwise null.
 * Keeps user-supplied garbage from reaching createOptRecord (which throws).
 */
export function parseValidIp(ip: string | null | undefined): string | null {
	if (!ip) return null;
	return isIPv4(ip) || isIPv6(ip) ? ip : null;
}

export function ip4ToNumber(ip: string): number {
	return (
		ip.split('.').reduce((int, octet) => {
			return (int << 8) + Number.parseInt(octet, 10);
		}, 0) >>> 0
	);
}

/**
 * Find the index of :: (double colon) in IPv6 parts.
 */
function findDoubleColonIndex(parts: string[]): number {
	for (let i = 1; i < parts.length - 1; i++) {
		if (parts[i] === '') return i;
	}
	return -1;
}

/**
 * Expand IPv6 parts into 8 full segments, handling :: expansion.
 */
function expandIPv6Segments(parts: string[]): string[] {
	const doubleColonIndex = findDoubleColonIndex(parts);
	const segments: string[] = [];

	for (let i = 0; i < parts.length; i++) {
		const part = parts[i];

		if (part === '') {
			// Handle :: expansion at the double colon position
			if (i === doubleColonIndex) {
				const nonEmptyCount = parts.filter((p) => p !== '').length;
				const zerosNeeded = 8 - nonEmptyCount;
				segments.push(...new Array(zerosNeeded).fill('0000'));
			}
			// Skip leading/trailing empty strings from split
			continue;
		}

		segments.push(part.padStart(4, '0'));
	}

	// Pad to exactly 8 segments
	while (segments.length < 8) {
		segments.push('0000');
	}

	return segments;
}

/**
 * Convert 8 hex segments to 16 bytes.
 */
function segmentsToBytes(segments: string[]): number[] {
	const bytes: number[] = [];
	for (let i = 0; i < 8; i++) {
		const value = Number.parseInt(segments[i] || '0000', 16);
		bytes.push((value >> 8) & 0xff, value & 0xff);
	}
	return bytes;
}

export function ipv6ToBytes(ipv6: string): number[] {
	const normalized = normalizeIPv6(ipv6);
	if (normalized === null) {
		throw new Error('Invalid IPv6 address: bad IPv4-mapped suffix');
	}
	const parts = normalized.split(':');
	const segments = expandIPv6Segments(parts);
	return segmentsToBytes(segments);
}

export function ipv6ToHex(ipv6: string): string {
	const bytes = ipv6ToBytes(ipv6);
	return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}