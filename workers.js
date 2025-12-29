/**
 * Country-Aware DNS over HTTPS (DoH) Worker
 *
 * Features:
 * - IPv4 & IPv6 support
 * - L1 (Memory) + L2 (Cache API) caching
 * - Upstream failover (Cloudflare primary, Google secondary)
 * - AAAA record parsing
 */

// ============================================================
// Global State & Cache
// ============================================================

let geoip_db = null;
const MEM_CACHE = new Map();
const MEM_CACHE_MAX_SIZE = 10000;
const CACHE_TTL_SECONDS = 86400; // 24 hours

// Upstream DNS servers (Cloudflare first for internal network optimization)
const UPSTREAM_ENDPOINTS = [
	'https://1.1.1.1/dns-query', // Cloudflare (Primary)
	'https://dns.google/dns-query', // Google (Secondary)
];

// ============================================================
// Main Handler
// ============================================================

export default {
	async fetch(request, env, ctx) {
		// Initialize D1 with session for read replication
		geoip_db ??= env.geolite2_country.withSession();

		const url = new URL(request.url);
		const params = url.pathname.substring(1).split('/');

		// Extract parameters
		const clientIp = env.connectingIp || extractParam(params, 'client-ip') || request.headers.get('cf-connecting-ip');
		const clientCountry = env.connectingIpCountry || extractParam(params, 'client-country') || request.headers.get('cf-ipcountry');

		// Alternative IP: from URL param, or fall back to client IP (for simplified URL)
		let alternativeIp = extractParam(params, 'alternative-ip');
		if (!alternativeIp) {
			// Check if first param looks like an IP address
			const firstParam = params[0];
			if (firstParam && /^[\d.:a-fA-F]+$/.test(firstParam) && (firstParam.includes('.') || firstParam.includes(':'))) {
				alternativeIp = firstParam;
			} else {
				// No alternative IP provided, use client IP for both queries
				alternativeIp = clientIp;
			}
		}

		// Parse DNS query
		let queryData;
		if (request.method === 'GET') {
			const dnsParam = url.searchParams.get('dns');
			if (!dnsParam) {
				return new Response('Missing dns parameter', { status: 400 });
			}
			const decodedQuery = atob(dnsParam);
			queryData = Uint8Array.from(decodedQuery, (c) => c.codePointAt(0));
		} else if (request.method === 'POST') {
			const originalQuery = await request.arrayBuffer();
			queryData = new Uint8Array(originalQuery);
		} else {
			return new Response('Unsupported method', { status: 405 });
		}

		// Smart DNS resolution with country matching
		async function queryDnsWithClientIp() {
			const response = await queryDns(queryData, clientIp);
			const buffer = await response.arrayBuffer();
			const dnsResponse = parseDnsResponse(buffer);

			if (!dnsResponse.answers.length || !clientIp) {
				return new Response(buffer, response);
			}

			const queryCountryInfoStart = Date.now();
			const responseIpSample = dnsResponse.answers[0];
			const responseIpCountry = await ip2country(responseIpSample.ip, ctx);
			const queryCountryInfoEnd = Date.now();

			console.log(`Response Sample: ${responseIpSample.ip} (${responseIpSample.type}), Country: ${responseIpCountry}`);
			console.log(`Query Country Info Time: ${queryCountryInfoEnd - queryCountryInfoStart}ms`);

			if (clientCountry === responseIpCountry) {
				return new Response(buffer, response);
			}
			return null;
		}

		const queryUpstreamStart = Date.now();
		const [response, alternativeResponse] = await Promise.all([queryDnsWithClientIp(), queryDns(queryData, alternativeIp)]);
		const queryUpstreamEnd = Date.now();

		console.log(`Query Upstream Time: ${queryUpstreamEnd - queryUpstreamStart}ms`);

		if (response) {
			return response;
		} else {
			return new Response(alternativeResponse.body, alternativeResponse);
		}
	},
};

// ============================================================
// Parameter Extraction
// ============================================================

function extractParam(params, name) {
	const index = params.indexOf(name);
	if (~index) {
		return params[index + 1];
	}
	return null;
}

// ============================================================
// DNS Query with Upstream Failover
// ============================================================

async function queryDns(queryData, clientIp) {
	let newQueryData = queryData;
	if (clientIp) {
		const [headerAndQuestion] = extractHeaderAndQuestion(queryData);
		const optRecord = createOptRecord(clientIp);
		newQueryData = combineQueryData(headerAndQuestion, optRecord);
	}

	const start = Date.now();

	// Try each upstream in order
	for (const endpoint of UPSTREAM_ENDPOINTS) {
		try {
			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout

			const response = await fetch(endpoint, {
				method: 'POST',
				headers: { 'Content-Type': 'application/dns-message' },
				body: newQueryData,
				signal: controller.signal,
			});

			clearTimeout(timeout);

			if (response.ok) {
				console.log(`DNS Query via ${endpoint}: ${Date.now() - start}ms`);
				return response;
			}
		} catch (err) {
			console.log(`Upstream ${endpoint} failed: ${err.message}`);
			// Continue to next upstream
		}
	}

	// All upstreams failed
	throw new Error('All DNS upstreams failed');
}

// ============================================================
// DNS Packet Manipulation
// ============================================================

function extractHeaderAndQuestion(data) {
	let offset = 12; // DNS header is 12 bytes
	const qdcount = (data[4] << 8) | data[5];

	for (let i = 0; i < qdcount; i++) {
		while (data[offset] !== 0) offset++;
		offset += 5;
	}

	return [data.subarray(0, offset), offset];
}

function createOptRecord(clientIp) {
	let ecsData;
	let family;

	if (isIPv4(clientIp)) {
		const ipParts = clientIp.split('.').map((part) => Number.parseInt(part, 10));
		family = 1;
		const prefixLength = 24; // Use /24 for better CDN locality
		ecsData = [0, 8, 0, 7, 0, family, prefixLength, 0, ...ipParts.slice(0, 3)];
	} else if (isIPv6(clientIp)) {
		const ipParts = ipv6ToBytes(clientIp);
		family = 2;
		const prefixLength = 48; // Use /48 for IPv6
		ecsData = [0, 8, 0, 10, 0, family, prefixLength, 0, ...ipParts.slice(0, 6)];
	} else {
		throw new Error('Invalid IP address');
	}

	return new Uint8Array([0, 0, 41, 16, 0, 0, 0, 0, 0, 0, ecsData.length, ...ecsData]);
}

function combineQueryData(headerAndQuestion, optRecord) {
	const newQueryData = new Uint8Array(headerAndQuestion.length + optRecord.length);
	newQueryData.set(headerAndQuestion, 0);
	newQueryData.set(optRecord, headerAndQuestion.length);
	newQueryData.set([32], 3);
	newQueryData.set([1], 11);
	return newQueryData;
}

// ============================================================
// IP Address Utilities
// ============================================================

function isIPv4(ip) {
	return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

function isIPv6(ip) {
	return ip.includes(':');
}

function ip4ToNumber(ip) {
	return (
		ip.split('.').reduce((int, octet) => {
			return (int << 8) + Number.parseInt(octet, 10);
		}, 0) >>> 0
	);
}

function ipv6ToBytes(ipv6) {
	let segments = ipv6.split(':');
	let expandedSegments = [];

	for (const segment of segments) {
		if (segment === '') {
			const zeroSegments = 8 - (segments.length - 1);
			expandedSegments.push(...new Array(zeroSegments).fill('0000'));
		} else {
			expandedSegments.push(segment.padStart(4, '0'));
		}
	}

	let bytes = [];
	for (let segment of expandedSegments) {
		const segmentValue = Number.parseInt(segment, 16);
		bytes.push((segmentValue >> 8) & 0xff, segmentValue & 0xff);
	}

	return bytes;
}

function ipv6ToHex(ipv6) {
	const bytes = ipv6ToBytes(ipv6);
	return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================
// IP to Country Lookup with Multi-Level Cache
// ============================================================

async function ip2country(ip, ctx) {
	// L1: Memory Cache
	if (MEM_CACHE.has(ip)) {
		return MEM_CACHE.get(ip);
	}

	// L2: Cache API
	const cache = caches.default;
	const cacheKey = new Request(`https://geoip.internal/${ip}`);
	let cachedResponse = await cache.match(cacheKey);

	if (cachedResponse) {
		const country = await cachedResponse.text();
		updateMemCache(ip, country);
		return country;
	}

	// L3: D1 Database Query
	let country;
	if (isIPv4(ip)) {
		country = await ip2countryIPv4(ip);
	} else {
		country = await ip2countryIPv6(ip);
	}

	if (country) {
		// Store in L1
		updateMemCache(ip, country);

		// Store in L2 (async, don't block response)
		ctx.waitUntil(
			cache.put(
				cacheKey,
				new Response(country, {
					headers: { 'Cache-Control': `max-age=${CACHE_TTL_SECONDS}` },
				})
			)
		);
	}

	return country;
}

function updateMemCache(ip, country) {
	// Simple LRU: if at capacity, clear half the cache
	if (MEM_CACHE.size >= MEM_CACHE_MAX_SIZE) {
		const keysToDelete = Array.from(MEM_CACHE.keys()).slice(0, MEM_CACHE_MAX_SIZE / 2);
		keysToDelete.forEach((key) => MEM_CACHE.delete(key));
	}
	MEM_CACHE.set(ip, country);
}

async function ip2countryIPv4(ip) {
	const ipNumber = ip4ToNumber(ip);
	const result = await geoip_db
		.prepare('SELECT country_iso_code FROM merged_ipv4_data WHERE network_start <= ?1 ORDER BY network_start DESC LIMIT 1;')
		.bind(ipNumber)
		.first();
	return result?.country_iso_code;
}

async function ip2countryIPv6(ip) {
	const hexIp = ipv6ToHex(ip);
	const result = await geoip_db
		.prepare('SELECT country_iso_code FROM merged_ipv6_data WHERE network_start <= ?1 ORDER BY network_start DESC LIMIT 1;')
		.bind(hexIp)
		.first();
	return result?.country_iso_code;
}

// ============================================================
// DNS Response Parser (A + AAAA Records)
// ============================================================

function parseDnsResponse(buffer) {
	const dnsResponse = new Uint8Array(buffer);
	let offset = 0;

	const id = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
	const flags = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
	const qdCount = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
	const anCount = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
	const nsCount = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
	const arCount = (dnsResponse[offset++] << 8) | dnsResponse[offset++];

	// Skip question section
	for (let i = 0; i < qdCount; i++) {
		while (dnsResponse[offset] !== 0) offset++;
		offset += 5;
	}

	// Parse answer section
	const answers = [];
	for (let i = 0; i < anCount; i++) {
		// Handle name compression
		if ((dnsResponse[offset] & 0xc0) === 0xc0) {
			offset += 2;
		} else {
			while (dnsResponse[offset] !== 0) offset++;
			offset++;
		}

		const type = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
		offset += 2; // Skip class
		offset += 4; // Skip TTL
		const dataLen = (dnsResponse[offset++] << 8) | dnsResponse[offset++];

		if (type === 1 && dataLen === 4) {
			// A record (IPv4)
			const ip = [];
			for (let j = 0; j < 4; j++) {
				ip.push(dnsResponse[offset++]);
			}
			answers.push({ type: 'A', ip: ip.join('.') });
		} else if (type === 28 && dataLen === 16) {
			// AAAA record (IPv6)
			const parts = [];
			for (let j = 0; j < 8; j++) {
				const segment = (dnsResponse[offset++] << 8) | dnsResponse[offset++];
				parts.push(segment.toString(16));
			}
			answers.push({ type: 'AAAA', ip: parts.join(':') });
		} else {
			offset += dataLen;
		}
	}

	return { id, flags, qdCount, anCount, nsCount, arCount, answers };
}
