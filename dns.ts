/**
 * Pure DNS packet functions: build / validate / parse / cache-prepare.
 * No state, no I/O — everything here is testable in isolation.
 */

import { isIPv4, isIPv6, ipv6ToBytes } from './ip';

export interface DnsAnswer {
	type: 'A' | 'AAAA';
	ip: string;
	ttl: number;
}

export interface DnsResponse {
	id: number;
	flags: number;
	qdCount: number;
	anCount: number;
	nsCount: number;
	arCount: number;
	answers: DnsAnswer[];
	minTtl: number; // Minimum TTL from all answers
}

export const DNS_TYPE_A = 1;
export const DNS_TYPE_AAAA = 28;

// RFC 1035 limits: label <= 63 octets, full name <= 253 octets (wire 255).
const MAX_LABEL_LENGTH = 63;
const MAX_NAME_LENGTH = 253;
// DoH query bodies are bounded by the DNS wire format maximum (RFC 8484).
export const MAX_DNS_MESSAGE_BYTES = 65535;
// base64url of a 65535-byte message, unpadded.
export const MAX_DNS_PARAM_LENGTH = 87380;

/** Thrown for client-supplied names/types that cannot form a valid query. */
export class InvalidDnsNameError extends Error {}

/**
 * Validate a client-supplied domain name and return its canonical form
 * (trailing dot stripped). Accepts ASCII LDH + underscore (SRV/DKIM-style
 * labels); internationalized names must arrive punycoded (xn--).
 * Throws InvalidDnsNameError so callers can answer 400 instead of 500.
 */
export function validateDomainName(name: string): string {
	const cleaned = name.endsWith('.') ? name.slice(0, -1) : name;
	if (!cleaned) {
		throw new InvalidDnsNameError('Empty domain name');
	}
	if (cleaned.length > MAX_NAME_LENGTH) {
		throw new InvalidDnsNameError(`Domain name longer than ${MAX_NAME_LENGTH} characters`);
	}
	if (!/^[\x20-\x7e]+$/.test(cleaned)) {
		throw new InvalidDnsNameError('Non-ASCII domain name; use punycode (xn--) form');
	}
	for (const label of cleaned.split('.')) {
		if (label.length === 0 || label.length > MAX_LABEL_LENGTH) {
			throw new InvalidDnsNameError(`Label length must be 1-${MAX_LABEL_LENGTH}: ${label.slice(0, 20)}...`);
		}
		if (!/^[a-zA-Z0-9_-]+$/.test(label)) {
			throw new InvalidDnsNameError('Invalid character in domain label (allowed: a-z 0-9 - _)');
		}
		if (label.startsWith('-') || label.endsWith('-')) {
			throw new InvalidDnsNameError('Label must not start or end with a hyphen');
		}
	}
	return cleaned;
}

/**
 * Build a DNS query packet for the given domain and type (A or AAAA).
 * The name is validated and canonicalized first.
 */
export function buildDnsQuery(name: string, type: string): Uint8Array {
	const cleaned = validateDomainName(name);
	const labels = cleaned.split('.');
	const qtype = type.toUpperCase() === 'AAAA' ? DNS_TYPE_AAAA : DNS_TYPE_A;

	let nameLen = 0;
	for (const label of labels) {
		nameLen += 1 + label.length;
	}
	nameLen += 1; // Null terminator

	const packet = new Uint8Array(12 + nameLen + 4);
	const view = new DataView(packet.buffer);
	const dnsId = crypto.getRandomValues(new Uint16Array(1))[0];

	// Header
	view.setUint16(0, dnsId); // ID
	view.setUint16(2, 0x0100); // Flags: standard query, recursion desired
	view.setUint16(4, 1); // QDCOUNT
	view.setUint16(6, 0); // ANCOUNT
	view.setUint16(8, 0); // NSCOUNT
	view.setUint16(10, 0); // ARCOUNT

	// Question section
	let offset = 12;
	for (const label of labels) {
		packet[offset++] = label.length;
		for (let i = 0; i < label.length; i++) {
			packet[offset++] = label.codePointAt(i) ?? 0; // ASCII guaranteed by validation
		}
	}
	packet[offset++] = 0; // Null terminator

	view.setUint16(offset, qtype); // QTYPE
	view.setUint16(offset + 2, 1); // QCLASS (IN)

	return packet;
}

/**
 * Structural validation of a client DNS query before any parse loop runs:
 * header length, QR=0, exactly one question, fully bounded label walk.
 * Returns null when valid, or a 400 Response when malformed.
 */
export function validateDnsQuery(data: Uint8Array): Response | null {
	if (data.length < 12) {
		return new Response('Malformed DNS query: shorter than header', { status: 400 });
	}
	if (data[2] & 0x80) {
		return new Response('Malformed DNS query: QR bit set (not a query)', { status: 400 });
	}
	const qdcount = (data[4] << 8) | data[5];
	if (qdcount !== 1) {
		return new Response('Malformed DNS query: expected exactly one question', { status: 400 });
	}
	let offset = 12;
	for (;;) {
		if (offset >= data.length) {
			return new Response('Malformed DNS query: truncated name', { status: 400 });
		}
		const len = data[offset];
		if (len === 0) {
			offset++;
			break;
		}
		if (len > 63) {
			return new Response('Malformed DNS query: invalid label length or compression pointer', { status: 400 });
		}
		offset += 1 + len;
	}
	if (offset + 4 > data.length) {
		return new Response('Malformed DNS query: truncated QTYPE/QCLASS', { status: 400 });
	}
	return null;
}

/**
 * Parse DNS query from request (GET or POST), with size caps so an oversized
 * body/parameter cannot be used for memory amplification.
 */
export async function parseDnsQuery(request: Request, url: URL): Promise<Uint8Array | Response> {
	if (request.method === 'GET') {
		const dnsParam = url.searchParams.get('dns');
		if (!dnsParam) {
			return new Response('Missing dns parameter', { status: 400 });
		}
		if (dnsParam.length > MAX_DNS_PARAM_LENGTH) {
			return new Response('dns parameter too large', { status: 400 });
		}
		try {
			// RFC 8484 GET uses base64url; atob only accepts the standard alphabet
			const decodedQuery = atob(dnsParam.replaceAll('-', '+').replaceAll('_', '/'));
			return Uint8Array.from(decodedQuery, (c) => c.codePointAt(0) ?? 0);
		} catch {
			return new Response('Invalid dns parameter encoding', { status: 400 });
		}
	}

	if (request.method === 'POST') {
		const contentLength = Number.parseInt(request.headers.get('content-length') ?? '', 10);
		if (!Number.isNaN(contentLength) && contentLength > MAX_DNS_MESSAGE_BYTES) {
			return new Response('DNS query body too large', { status: 413 });
		}
		const originalQuery = await request.arrayBuffer();
		if (originalQuery.byteLength > MAX_DNS_MESSAGE_BYTES) {
			return new Response('DNS query body too large', { status: 413 });
		}
		return new Uint8Array(originalQuery);
	}

	return new Response('Unsupported method', { status: 405 });
}

/**
 * Skip a DNS name (handles both compressed and uncompressed formats).
 * Returns the new offset after skipping the name.
 */
export function skipDnsName(data: Uint8Array, offset: number): number {
	if (offset < data.length && (data[offset] & 0xc0) === 0xc0) {
		return offset + 2; // Compressed name pointer
	}
	while (offset < data.length && data[offset] !== 0) offset++;
	return offset + 1;
}

/**
 * Prepare a cached DNS response for the current query, in a single copy:
 * - rewrite the message ID to the current query's ID (strict RFC 8484
 *   clients discard ID-mismatched responses);
 * - age answer TTLs by the time already spent in cache, so clients do not
 *   extend record lifetimes beyond the authoritative TTL.
 * The stored cache buffer is never mutated. On any structural inconsistency
 * the ID-rewritten (unaged) copy is returned — fail open, never corrupt.
 */
export function prepareCachedResponse(cached: ArrayBuffer, queryData: Uint8Array, elapsedSeconds: number): ArrayBuffer {
	if (cached.byteLength < 12 || queryData.length < 2) {
		return cached;
	}
	const out = new Uint8Array(cached.slice(0));
	out[0] = queryData[0];
	out[1] = queryData[1];

	const elapsed = Math.floor(elapsedSeconds);
	if (elapsed <= 0) {
		return out.buffer;
	}
	const view = new DataView(out.buffer);
	const qdCount = view.getUint16(4);
	const anCount = view.getUint16(6);
	let offset = 12;
	for (let i = 0; i < qdCount; i++) {
		offset = skipDnsName(out, offset) + 4; // QTYPE(2) + QCLASS(2)
		if (offset > out.length) return out.buffer;
	}
	// Answer section only: authority/additional TTLs are left as-is (clients
	// key their caching on answer TTLs).
	for (let i = 0; i < anCount; i++) {
		offset = skipDnsName(out, offset);
		if (offset + 10 > out.length) return out.buffer;
		const ttl = view.getUint32(offset + 4);
		view.setUint32(offset + 4, Math.max(0, ttl - elapsed));
		const dataLen = view.getUint16(offset + 8);
		offset += 10 + dataLen;
		if (offset > out.length) return out.buffer;
	}
	return out.buffer;
}

/**
 * Extract header + question section (validated queries: exactly one question,
 * no compression pointers — validateDnsQuery guarantees both).
 */
export function extractHeaderAndQuestion(data: Uint8Array): [Uint8Array, number] {
	let offset = 12; // DNS header is 12 bytes
	const qdcount = (data[4] << 8) | data[5];

	for (let i = 0; i < qdcount; i++) {
		while (offset < data.length && data[offset] !== 0) offset++;
		offset += 5;
	}

	return [data.subarray(0, offset), offset];
}

export function createOptRecord(clientIp: string): Uint8Array {
	let ecsData: number[];
	let family: number;

	if (isIPv4(clientIp)) {
		const ipParts = clientIp.split('.').map((part) => Number.parseInt(part, 10));
		if (ipParts.some((p) => p < 0 || p > 255 || Number.isNaN(p))) {
			throw new Error('Invalid IPv4 address: octet out of range');
		}
		family = 1;
		const prefixLength = 24; // /24 for better CDN locality
		ecsData = [0, 8, 0, 7, 0, family, prefixLength, 0, ...ipParts.slice(0, 3)];
	} else if (isIPv6(clientIp)) {
		const ipParts = ipv6ToBytes(clientIp);
		if (ipParts.length !== 16) {
			throw new Error('Invalid IPv6 address: incorrect byte length');
		}
		family = 2;
		const prefixLength = 48; // /48 for IPv6
		ecsData = [0, 8, 0, 10, 0, family, prefixLength, 0, ...ipParts.slice(0, 6)];
	} else {
		throw new Error('Invalid IP address format');
	}

	return new Uint8Array([0, 0, 41, 16, 0, 0, 0, 0, 0, 0, ecsData.length, ...ecsData]);
}

/**
 * Append the OPT record. ARCOUNT is written as a full 16-bit field.
 * forceAd=true ORs the AD bit (request upstream DNSSEC validation, the
 * historical behavior); false preserves the client's own AD/CD/Z bits.
 */
export function combineQueryData(headerAndQuestion: Uint8Array, optRecord: Uint8Array, forceAd: boolean): Uint8Array {
	const newQueryData = new Uint8Array(headerAndQuestion.length + optRecord.length);
	newQueryData.set(headerAndQuestion, 0);
	newQueryData.set(optRecord, headerAndQuestion.length);
	if (forceAd) {
		newQueryData[3] |= 0x20; // set AD; preserve the client's CD/Z bits
	}
	const view = new DataView(newQueryData.buffer);
	view.setUint16(10, 1); // ARCOUNT = 1 (the OPT record), both bytes
	return newQueryData;
}

function parseARecord(data: Uint8Array, offset: number, ttl: number): DnsAnswer {
	const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
	return { type: 'A', ip, ttl };
}

function parseAAAARecord(data: Uint8Array, offset: number, ttl: number): DnsAnswer {
	const parts: string[] = [];
	for (let j = 0; j < 8; j++) {
		const segment = (data[offset + j * 2] << 8) | data[offset + j * 2 + 1];
		parts.push(segment.toString(16));
	}
	return { type: 'AAAA', ip: parts.join(':'), ttl };
}

function parseAnswerRecord(data: Uint8Array, offset: number): { answer: DnsAnswer | null; newOffset: number } {
	offset = skipDnsName(data, offset);

	const type = (data[offset] << 8) | data[offset + 1];
	// TTL is at offset+4 to offset+7 (4 bytes, big-endian)
	const ttl = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
	const dataLen = (data[offset + 8] << 8) | data[offset + 9];
	offset += 10; // Skip type(2) + class(2) + TTL(4) + dataLen(2)

	let answer: DnsAnswer | null = null;
	if (type === DNS_TYPE_A && dataLen === 4) {
		answer = parseARecord(data, offset, ttl);
	} else if (type === DNS_TYPE_AAAA && dataLen === 16) {
		answer = parseAAAARecord(data, offset, ttl);
	}

	return { answer, newOffset: offset + dataLen };
}

/**
 * Parse DNS response buffer. Throws on buffers shorter than the header so
 * callers degrade explicitly instead of reading undefined bytes.
 */
export function parseDnsResponse(buffer: ArrayBuffer): DnsResponse {
	if (buffer.byteLength < 12) {
		throw new Error('DNS response shorter than header');
	}
	const data = new Uint8Array(buffer);
	const view = new DataView(buffer);
	let offset = 0;

	const id = view.getUint16(0);
	const flags = view.getUint16(2);
	const qdCount = view.getUint16(4);
	const anCount = view.getUint16(6);
	const nsCount = view.getUint16(8);
	const arCount = view.getUint16(10);
	offset = 12;

	// Skip question section
	for (let i = 0; i < qdCount; i++) {
		offset = skipDnsName(data, offset) + 4; // Skip QTYPE(2) + QCLASS(2)
	}

	// Parse answer section with inline minTtl calculation
	const answers: DnsAnswer[] = [];
	let minTtl = Infinity;

	for (let i = 0; i < anCount; i++) {
		const { answer, newOffset } = parseAnswerRecord(data, offset);
		if (answer) {
			answers.push(answer);
			if (answer.ttl < minTtl) minTtl = answer.ttl;
		}
		offset = newOffset;
	}

	const finalMinTtl = minTtl === Infinity ? 0 : minTtl;

	return { id, flags, qdCount, anCount, nsCount, arCount, answers, minTtl: finalMinTtl };
}