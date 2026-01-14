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
// Type Definitions
// ============================================================

interface Env {
	geolite2_country: D1Database;
	connectingIp?: string;
	connectingIpCountry?: string;
	// Config
	MEM_CACHE_MAX_SIZE?: string;
	CACHE_TTL_SECONDS?: string;
	DEBUG?: string;
	COUNTRY_PRIORITY?: string;
}

interface DnsAnswer {
	type: 'A' | 'AAAA';
	ip: string;
	ttl: number;
}

interface DnsResponse {
	id: number;
	flags: number;
	qdCount: number;
	anCount: number;
	nsCount: number;
	arCount: number;
	answers: DnsAnswer[];
	minTtl: number; // Minimum TTL from all answers
}

interface GeoIpResult {
	country_iso_code: string;
}

// ============================================================
// Global State & Cache
// ============================================================

let geoip_db: D1Database | null = null;
const MEM_CACHE = new Map<string, string>();

// DNS Response Cache (L1 Memory)
const DNS_CACHE = new Map<string, { data: ArrayBuffer; expires: number; ttl: number }>();
const DNS_CACHE_MAX_SIZE = 5000;

// Defaults
let MEM_CACHE_MAX_SIZE = 10000;
let CACHE_TTL_SECONDS = 86400; // 24 hours
let DEBUG = false;

// DNS Cache Config
const DNS_CACHE_CONFIG = {
	minTtl: 60,       // Minimum 60 seconds
	maxTtl: 3600,     // Maximum 1 hour
	negativeTtl: 300, // NXDOMAIN cache 5 minutes
	prefetchThreshold: 0.2, // Prefetch when remaining TTL < 20%
};

// Statistics (in-memory, resets on worker restart)
const STATS = {
	requests: { total: 0, doh: 0, json: 0, health: 0, debug: 0 },
	cache: { memHits: 0, apiHits: 0, misses: 0 },
	dns: { cacheHits: 0, cacheMisses: 0, negativeHits: 0, prefetches: 0 },
	errors: 0,
	startTime: Date.now(),
};

function log(...args: any[]) {
	if (DEBUG) {
		console.log(...args);
	}
}

// Country priority list for smart routing
// If response IP country matches any in this list, prefer it based on priority order
// Can be overridden via COUNTRY_PRIORITY env var (comma-separated)
let COUNTRY_PRIORITY: string[] = ['CN', 'HK', 'TW', 'JP', 'SG', 'US'];

// Upstream DNS servers (Cloudflare first for internal network optimization)
const UPSTREAM_ENDPOINTS = [
	'https://1.1.1.1/dns-query', // Cloudflare (Primary)
	'https://dns.google/dns-query', // Google (Secondary)
];

// ============================================================
// Main Handler
// ============================================================

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Initialize Config
		if (env.MEM_CACHE_MAX_SIZE) MEM_CACHE_MAX_SIZE = Number.parseInt(env.MEM_CACHE_MAX_SIZE, 10) || 10000;
		if (env.CACHE_TTL_SECONDS) CACHE_TTL_SECONDS = Number.parseInt(env.CACHE_TTL_SECONDS, 10) || 86400;
		DEBUG = env.DEBUG === 'true';
		if (env.COUNTRY_PRIORITY) {
			COUNTRY_PRIORITY = env.COUNTRY_PRIORITY.split(',').map(c => c.trim().toUpperCase());
		}


		// Initialize D1 straight from bindings for best read performance
		geoip_db ??= env.geolite2_country;

		const url = new URL(request.url);
		const path = url.pathname;

		// Handle CORS preflight
		if (request.method === 'OPTIONS') {
			return handleCors(new Response(null, { status: 204 }));
		}

		// Track total requests
		STATS.requests.total++;

		// API Routing
		if (path === '/health') {
			STATS.requests.health++;
			return handleCors(await handleHealth());
		}

		if (path === '/stats') {
			return handleCors(handleStats());
		}

		if (path === '/resolve') {
			STATS.requests.json++;
			return handleCors(await handleJsonDns(url, ctx));
		}

		if (path.startsWith('/debug/ip/')) {
			STATS.requests.debug++;
			const ip = path.substring('/debug/ip/'.length);
			return handleCors(await handleDebugIp(ip, ctx));
		}

		// Legacy DoH endpoint
		STATS.requests.doh++;
		return handleCors(await handleDoH(request, url, env, ctx));
	},
};

// ============================================================
// CORS Handler
// ============================================================

function handleCors(response: Response): Response {
	const headers = new Headers(response.headers);
	headers.set('Access-Control-Allow-Origin', '*');
	headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	headers.set('Access-Control-Allow-Headers', 'Content-Type, Accept');
	headers.set('Access-Control-Max-Age', '86400');
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

// ============================================================
// Health Check Endpoint
// ============================================================

async function handleHealth(): Promise<Response> {
	const status = {
		status: 'ok',
		timestamp: new Date().toISOString(),
		cache: {
			geoip: {
				memorySize: MEM_CACHE.size,
				maxSize: MEM_CACHE_MAX_SIZE,
			},
			dns: {
				memorySize: DNS_CACHE.size,
				maxSize: DNS_CACHE_MAX_SIZE,
			},
			ttlSeconds: CACHE_TTL_SECONDS,
		},
		database: geoip_db ? 'connected' : 'disconnected',
	};
	return new Response(JSON.stringify(status, null, 2), {
		headers: { 'Content-Type': 'application/json' },
	});
}

// ============================================================
// Statistics Endpoint
// ============================================================

function handleStats(): Response {
	const uptime = Math.floor((Date.now() - STATS.startTime) / 1000);
	const totalCacheOps = STATS.cache.memHits + STATS.cache.apiHits + STATS.cache.misses;
	const totalDnsOps = STATS.dns.cacheHits + STATS.dns.cacheMisses;

	const stats = {
		uptime: `${uptime}s`,
		requests: STATS.requests,
		geoipCache: {
			...STATS.cache,
			hitRate: totalCacheOps > 0 
				? ((STATS.cache.memHits + STATS.cache.apiHits) / totalCacheOps).toFixed(3)
				: 'N/A',
		},
		dnsCache: {
			...STATS.dns,
			hitRate: totalDnsOps > 0
				? (STATS.dns.cacheHits / totalDnsOps).toFixed(3)
				: 'N/A',
		},
		errors: STATS.errors,
	};

	return new Response(JSON.stringify(stats, null, 2), {
		headers: { 'Content-Type': 'application/json' },
	});
}

// ============================================================
// JSON DNS API Endpoint
// ============================================================

interface JsonDnsResponse {
	Status: number;
	TC: boolean;
	RD: boolean;
	RA: boolean;
	AD: boolean;
	CD: boolean;
	Question: { name: string; type: number }[];
	Answer?: { name: string; type: number; TTL: number; data: string }[];
	Comment?: string;
}

async function handleJsonDns(url: URL, ctx: ExecutionContext): Promise<Response> {
	const name = url.searchParams.get('name');
	const type = url.searchParams.get('type') || 'A';

	if (!name) {
		return new Response(JSON.stringify({ error: 'Missing name parameter' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	try {
		// Build DNS query
		const queryData = buildDnsQuery(name, type);

		// Query upstream
		const response = await queryDns(queryData, null);
		const buffer = await response.arrayBuffer();
		const dnsResponse = parseDnsResponse(buffer);

		// Format JSON response (Google DNS JSON API compatible)
		const jsonResponse: JsonDnsResponse = {
			Status: (dnsResponse.flags >> 11) & 0xf,
			TC: ((dnsResponse.flags >> 9) & 1) === 1,
			RD: ((dnsResponse.flags >> 8) & 1) === 1,
			RA: ((dnsResponse.flags >> 7) & 1) === 1,
			AD: ((dnsResponse.flags >> 5) & 1) === 1,
			CD: ((dnsResponse.flags >> 4) & 1) === 1,
			Question: [{ name, type: type === 'AAAA' ? 28 : 1 }],
			Answer: dnsResponse.answers.map((a) => ({
				name,
				type: a.type === 'AAAA' ? 28 : 1,
				TTL: 300, // Default TTL
				data: a.ip,
			})),
		};

		return new Response(JSON.stringify(jsonResponse, null, 2), {
			headers: { 'Content-Type': 'application/json' },
		});
	} catch (err) {
		const error = err as Error;
		return new Response(JSON.stringify({ error: error.message }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Build a DNS query packet for the given domain and type.
 */
function buildDnsQuery(name: string, type: string): Uint8Array {
	const labels = name.split('.');
	const qtype = type.toUpperCase() === 'AAAA' ? 28 : 1;

	// Calculate total length
	let nameLen = 0;
	for (const label of labels) {
		nameLen += 1 + label.length;
	}
	nameLen += 1; // Null terminator

	const packet = new Uint8Array(12 + nameLen + 4);
	const view = new DataView(packet.buffer);

	// Header
	view.setUint16(0, Math.floor(Math.random() * 65535)); // ID
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
			packet[offset++] = label.codePointAt(i) ?? 0;
		}
	}
	packet[offset++] = 0; // Null terminator

	view.setUint16(offset, qtype); // QTYPE
	view.setUint16(offset + 2, 1); // QCLASS (IN)

	return packet;
}

// ============================================================
// IP Debug Endpoint
// ============================================================

async function handleDebugIp(ip: string, ctx: ExecutionContext): Promise<Response> {
	if (!ip) {
		return new Response(JSON.stringify({ error: 'Missing IP address' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	const isV4 = isIPv4(ip);
	const isV6 = isIPv6(ip);

	if (!isV4 && !isV6) {
		return new Response(JSON.stringify({ error: 'Invalid IP address format' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	const country = await ip2country(ip, ctx);
	const inCache = MEM_CACHE.has(ip);

	const result = {
		ip,
		type: isV4 ? 'IPv4' : 'IPv6',
		country: country || 'unknown',
		cached: inCache,
		timestamp: new Date().toISOString(),
	};

	return new Response(JSON.stringify(result, null, 2), {
		headers: { 'Content-Type': 'application/json' },
	});
}

// ============================================================
// Legacy DoH Handler
// ============================================================

async function handleDoH(request: Request, url: URL, env: Env, ctx: ExecutionContext): Promise<Response> {
	const params = url.pathname.substring(1).split('/');

	// Extract parameters
	const clientIp = env.connectingIp || extractParam(params, 'client-ip') || request.headers.get('cf-connecting-ip');
	const clientCountry = env.connectingIpCountry || extractParam(params, 'client-country') || request.headers.get('cf-ipcountry');

	// Alternative IP: from URL param, or fall back to client IP (for simplified URL)
	const alternativeIp = parseAlternativeIp(params, clientIp);

	// Parse DNS query
	const queryResult = await parseDnsQuery(request, url);
	if (queryResult instanceof Response) {
		return queryResult;
	}
	const queryData = queryResult;

	// Smart DNS resolution with country matching
	async function queryDnsWithClientIp(): Promise<{ response: Response; country: string | null; priority: number }> {
		const response = await queryDns(queryData, clientIp, ctx);
		const buffer = await response.arrayBuffer();
		const dnsResponse = parseDnsResponse(buffer);

		if (!dnsResponse.answers.length) {
			return { response: new Response(buffer, response), country: null, priority: -1 };
		}

		const responseIpSample = dnsResponse.answers[0];
		const responseIpCountry = await ip2country(responseIpSample.ip, ctx);
		const priority = responseIpCountry 
			? COUNTRY_PRIORITY.indexOf(responseIpCountry)
			: -1;

		log(`Client IP response: ${responseIpSample.ip}, Country: ${responseIpCountry}, Priority: ${priority}`);

		return { 
			response: new Response(buffer, response), 
			country: responseIpCountry, 
			priority: priority >= 0 ? priority : 999 // Not in list = lowest priority
		};
	}

	async function queryDnsWithAltIp(): Promise<{ response: Response; country: string | null; priority: number }> {
		const response = await queryDns(queryData, alternativeIp, ctx);
		const buffer = await response.arrayBuffer();
		const dnsResponse = parseDnsResponse(buffer);

		if (!dnsResponse.answers.length) {
			return { response: new Response(buffer, response), country: null, priority: -1 };
		}

		const responseIpSample = dnsResponse.answers[0];
		const responseIpCountry = await ip2country(responseIpSample.ip, ctx);
		const priority = responseIpCountry 
			? COUNTRY_PRIORITY.indexOf(responseIpCountry)
			: -1;

		log(`Alt IP response: ${responseIpSample.ip}, Country: ${responseIpCountry}, Priority: ${priority}`);

		return { 
			response: new Response(buffer, response), 
			country: responseIpCountry, 
			priority: priority >= 0 ? priority : 999
		};
	}

	const queryUpstreamStart = Date.now();
	const [clientResult, altResult] = await Promise.all([queryDnsWithClientIp(), queryDnsWithAltIp()]);
	const queryUpstreamEnd = Date.now();

	log(`Query Upstream Time: ${queryUpstreamEnd - queryUpstreamStart}ms`);

	// Client country exact match takes highest priority
	if (clientCountry && clientResult.country === clientCountry) {
		log(`Selected: Client IP response (exact country match: ${clientCountry})`);
		return clientResult.response;
	}

	// Otherwise, select by priority list
	if (clientResult.priority <= altResult.priority) {
		log(`Selected: Client IP response (priority: ${clientResult.priority} vs ${altResult.priority})`);
		return clientResult.response;
	} else {
		log(`Selected: Alt IP response (priority: ${altResult.priority} vs ${clientResult.priority})`);
		return altResult.response;
	}
}

// ============================================================
// ============================================================
// Parameter Extraction
// ============================================================

function extractParam(params: string[], name: string): string | null {
	const index = params.indexOf(name);
	if (~index) {
		return params[index + 1] ?? null;
	}
	return null;
}

/**
 * Parse alternative IP from URL params or first path segment.
 */
function parseAlternativeIp(params: string[], clientIp: string | null): string | null {
	const explicitAltIp = extractParam(params, 'alternative-ip');
	if (explicitAltIp) return explicitAltIp;

	const firstParam = params[0];
	const looksLikeIp = firstParam && /^[\d.:a-fA-F]+$/.test(firstParam);
	const hasIpDelimiter = firstParam?.includes('.') || firstParam?.includes(':');

	if (looksLikeIp && hasIpDelimiter) {
		return firstParam;
	}
	return clientIp;
}

/**
 * Parse DNS query from request (GET or POST).
 */
async function parseDnsQuery(request: Request, url: URL): Promise<Uint8Array | Response> {
	if (request.method === 'GET') {
		const dnsParam = url.searchParams.get('dns');
		if (!dnsParam) {
			return new Response('Missing dns parameter', { status: 400 });
		}
		try {
			const decodedQuery = atob(dnsParam);
			return Uint8Array.from(decodedQuery, (c) => c.codePointAt(0) ?? 0);
		} catch {
			return new Response('Invalid dns parameter encoding', { status: 400 });
		}
	}

	if (request.method === 'POST') {
		const originalQuery = await request.arrayBuffer();
		return new Uint8Array(originalQuery);
	}

	return new Response('Unsupported method', { status: 405 });
}

// ============================================================
// DNS Query with Upstream Failover
// ============================================================

async function queryDns(queryData: Uint8Array, clientIp: string | null, ctx?: ExecutionContext): Promise<Response> {
	// Generate cache key based on query + ECS prefix
	const cacheKey = generateDnsCacheKey(queryData, clientIp);
	
	// Check L1 Memory Cache
	const cachedEntry = DNS_CACHE.get(cacheKey);
	if (cachedEntry && cachedEntry.expires > Date.now()) {
		STATS.dns.cacheHits++;
		log(`DNS Cache HIT (memory): ${cacheKey}`);
		
		// Check if we need to prefetch (remaining TTL < threshold)
		const remainingMs = cachedEntry.expires - Date.now();
		const totalTtlMs = (cachedEntry.ttl || 300) * 1000;
		const remainingRatio = remainingMs / totalTtlMs;
		
		if (ctx && remainingRatio < DNS_CACHE_CONFIG.prefetchThreshold) {
			// Trigger background prefetch
			STATS.dns.prefetches++;
			log(`DNS Prefetch triggered: ${cacheKey}, remaining: ${Math.round(remainingRatio * 100)}%`);
			ctx.waitUntil(prefetchDns(queryData, clientIp, cacheKey));
		}
		
		return new Response(cachedEntry.data, {
			headers: { 'Content-Type': 'application/dns-message' },
		});
	}

	// Check L2 Cache API
	const cache = caches.default;
	const cacheUrl = new Request(`https://dns-cache.internal/${cacheKey}`);
	const cachedResponse = await cache.match(cacheUrl);
	if (cachedResponse) {
		STATS.dns.cacheHits++;
		log(`DNS Cache HIT (cache api): ${cacheKey}`);
		// Warm up L1 cache
		const buffer = await cachedResponse.clone().arrayBuffer();
		
		// Use remaining TTL from X-Expires-At, fall back to 60s
		let ttl = 60;
		const expiresAtStr = cachedResponse.headers.get('X-Expires-At');
		if (expiresAtStr) {
			const expiresAt = Number.parseInt(expiresAtStr, 10);
			if (!Number.isNaN(expiresAt)) {
				ttl = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
			}
		}
		
		// Skip L1 cache if already expired
		if (ttl <= 0) {
			log(`Skipping L1 cache: TTL expired (${cacheKey})`);
			return new Response(buffer, {
				headers: { 'Content-Type': 'application/dns-message' },
			});
		}
		
		updateDnsCache(cacheKey, buffer, ttl);
		return new Response(buffer, {
			headers: { 'Content-Type': 'application/dns-message' },
		});
	}

	STATS.dns.cacheMisses++;

	// Query upstream
	const response = await queryDnsUpstream(queryData, clientIp);
	const buffer = await response.arrayBuffer();

	// Parse response to get TTL and check for NXDOMAIN
	const dnsResponse = parseDnsResponse(buffer);
	const rcode = dnsResponse.flags & 0xf;
	
	let ttl: number;
	if (rcode === 3) {
		// NXDOMAIN - use negative TTL
		ttl = DNS_CACHE_CONFIG.negativeTtl;
		STATS.dns.negativeHits++;
		log(`DNS NXDOMAIN cached: ${cacheKey}, TTL: ${ttl}s`);
	} else if (dnsResponse.answers.length > 0) {
		// Use real TTL from DNS response, bounded by config limits
		ttl = Math.min(Math.max(dnsResponse.minTtl, DNS_CACHE_CONFIG.minTtl), DNS_CACHE_CONFIG.maxTtl);
		log(`DNS Response cached: ${cacheKey}, realTTL: ${dnsResponse.minTtl}s, boundedTTL: ${ttl}s, answers: ${dnsResponse.answers.length}`);
	} else {
		// No answers, minimal cache
		ttl = DNS_CACHE_CONFIG.minTtl;
	}

	// Update L1 cache
	updateDnsCache(cacheKey, buffer, ttl);

	// Update L2 cache (async)
	const cacheResponse = new Response(buffer, {
		headers: {
			'Content-Type': 'application/dns-message',
			'Cache-Control': `max-age=${ttl}`,
			'X-Expires-At': `${Date.now() + ttl * 1000}`,
		},
	});
	// Don't await, let it run in background
	cache.put(cacheUrl, cacheResponse).catch((err) => {
		STATS.errors++;
		log(`Cache put failed: ${err.message || err}`);
	});

	return new Response(buffer, {
		headers: { 'Content-Type': 'application/dns-message' },
	});
}

/**
 * Generate cache key from DNS query data and client IP prefix.
 */
function generateDnsCacheKey(queryData: Uint8Array, clientIp: string | null): string {
	// Extract domain name and type from query
	let offset = 12; // Skip header
	let domain = '';
	while (queryData[offset] !== 0) {
		const len = queryData[offset];
		if (domain) domain += '.';
		for (let i = 1; i <= len; i++) {
			domain += String.fromCodePoint(queryData[offset + i] ?? 0);
		}
		offset += len + 1;
	}
	offset++; // Skip null terminator
	const qtype = (queryData[offset] << 8) | queryData[offset + 1];
	
	// Get IP prefix for ECS-aware caching
	let ipPrefix = 'none';
	if (clientIp) {
		if (isIPv4(clientIp)) {
			// Use /24 prefix
			ipPrefix = clientIp.split('.').slice(0, 3).join('.');
		} else if (isIPv6(clientIp)) {
			// Use /48 prefix (first 3 segments)
			ipPrefix = clientIp.split(':').slice(0, 3).join(':');
		}
	}
	
	return `${domain}:${qtype}:${ipPrefix}`;
}

/**
 * Update DNS response cache with LRU eviction.
 */
function updateDnsCache(key: string, data: ArrayBuffer, ttlSeconds: number): void {
	// LRU: Remove oldest if at capacity
	if (DNS_CACHE.size >= DNS_CACHE_MAX_SIZE) {
		const oldestKey = DNS_CACHE.keys().next().value;
		if (oldestKey) DNS_CACHE.delete(oldestKey);
	}
	DNS_CACHE.set(key, {
		data,
		expires: Date.now() + ttlSeconds * 1000,
		ttl: ttlSeconds,
	});
}

/**
 * Prefetch DNS response in background before cache expires.
 */
async function prefetchDns(queryData: Uint8Array, clientIp: string | null, cacheKey: string): Promise<void> {
	try {
		const response = await queryDnsUpstream(queryData, clientIp);
		const buffer = await response.arrayBuffer();
		
		const dnsResponse = parseDnsResponse(buffer);
		if (dnsResponse.answers.length > 0) {
			const ttl = Math.min(Math.max(dnsResponse.minTtl, DNS_CACHE_CONFIG.minTtl), DNS_CACHE_CONFIG.maxTtl);
			updateDnsCache(cacheKey, buffer, ttl);
			
			// Also update L2 cache
			const cache = caches.default;
			const cacheUrl = new Request(`https://dns-cache.internal/${cacheKey}`);
			const cacheResponse = new Response(buffer, {
				headers: {
					'Content-Type': 'application/dns-message',
					'Cache-Control': `max-age=${ttl}`,
					'X-Expires-At': `${Date.now() + ttl * 1000}`,
				},
			});
			await cache.put(cacheUrl, cacheResponse);
			
			log(`DNS Prefetch completed: ${cacheKey}, TTL: ${ttl}s`);
		}
	} catch (err) {
		const error = err as Error;
		log(`DNS Prefetch failed: ${cacheKey}, error: ${error.message}`);
	}
}

/**
 * Query upstream DNS servers with failover.
 */
async function queryDnsUpstream(queryData: Uint8Array, clientIp: string | null): Promise<Response> {
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
				log(`DNS Query via ${endpoint}: ${Date.now() - start}ms`);
				return response;
			}
		} catch (err) {
			const error = err as Error;
			log(`Upstream ${endpoint} failed: ${error.message}`);
			// Continue to next upstream
		}
	}

	// All upstreams failed
	STATS.errors++;
	throw new Error('All DNS upstreams failed');
}

// ============================================================
// DNS Packet Manipulation
// ============================================================

function extractHeaderAndQuestion(data: Uint8Array): [Uint8Array, number] {
	let offset = 12; // DNS header is 12 bytes
	const qdcount = (data[4] << 8) | data[5];

	for (let i = 0; i < qdcount; i++) {
		while (data[offset] !== 0) offset++;
		offset += 5;
	}

	return [data.subarray(0, offset), offset];
}

function createOptRecord(clientIp: string): Uint8Array {
	let ecsData: number[];
	let family: number;

	if (isIPv4(clientIp)) {
		const ipParts = clientIp.split('.').map((part) => Number.parseInt(part, 10));
		// Validate IPv4 octets are in valid range
		if (ipParts.some((p) => p < 0 || p > 255 || Number.isNaN(p))) {
			throw new Error('Invalid IPv4 address: octet out of range');
		}
		family = 1;
		const prefixLength = 24; // Use /24 for better CDN locality
		ecsData = [0, 8, 0, 7, 0, family, prefixLength, 0, ...ipParts.slice(0, 3)];
	} else if (isIPv6(clientIp)) {
		const ipParts = ipv6ToBytes(clientIp);
		if (ipParts.length !== 16) {
			throw new Error('Invalid IPv6 address: incorrect byte length');
		}
		family = 2;
		const prefixLength = 48; // Use /48 for IPv6
		ecsData = [0, 8, 0, 10, 0, family, prefixLength, 0, ...ipParts.slice(0, 6)];
	} else {
		throw new Error('Invalid IP address format');
	}

	return new Uint8Array([0, 0, 41, 16, 0, 0, 0, 0, 0, 0, ecsData.length, ...ecsData]);
}

function combineQueryData(headerAndQuestion: Uint8Array, optRecord: Uint8Array): Uint8Array {
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

function isIPv4(ip: string): boolean {
	return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

function isIPv6(ip: string): boolean {
	// Basic IPv6 format validation
	if (!ip.includes(':')) return false;
	// Check for valid characters and structure
	const parts = ip.split(':');
	if (parts.length < 3 || parts.length > 8) return false;
	// Allow only one :: (empty string sequence)
	const emptyParts = parts.filter((p) => p === '').length;
	if (emptyParts > 2) return false; // More than one :: is invalid
	// Validate each segment
	for (const part of parts) {
		if (part === '') continue; // Empty for ::
		if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
	}
	return true;
}

function ip4ToNumber(ip: string): number {
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

function ipv6ToBytes(ipv6: string): number[] {
	const parts = ipv6.split(':');
	const segments = expandIPv6Segments(parts);
	return segmentsToBytes(segments);
}

function ipv6ToHex(ipv6: string): string {
	const bytes = ipv6ToBytes(ipv6);
	return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================
// IP to Country Lookup with Multi-Level Cache
// ============================================================

async function ip2country(ip: string, ctx: ExecutionContext): Promise<string | null> {
	// Validate IP format
	if (!isIPv4(ip) && !isIPv6(ip)) {
		return null;
	}

	// L1: Memory Cache
	if (MEM_CACHE.has(ip)) {
		const country = MEM_CACHE.get(ip)!;
		// LRU: Refresh position
		MEM_CACHE.delete(ip);
		MEM_CACHE.set(ip, country);
		return country;
	}

	// L2: Cache API
	const cache = caches.default;
	const cacheKey = new Request(`https://geoip.internal/${ip}`);
	const cachedResponse = await cache.match(cacheKey);

	if (cachedResponse) {
		const country = await cachedResponse.text();
		updateMemCache(ip, country);
		return country;
	}

	// L3: D1 Database Query
	let country: string | null = null;
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

function updateMemCache(ip: string, country: string): void {
	// LRU: If key exists, delete first to update position
	if (MEM_CACHE.has(ip)) {
		MEM_CACHE.delete(ip);
	} else if (MEM_CACHE.size >= MEM_CACHE_MAX_SIZE) {
		// If at capacity, delete the oldest (first) item
		const oldestKey = MEM_CACHE.keys().next().value;
		if (oldestKey) MEM_CACHE.delete(oldestKey);
	}
	MEM_CACHE.set(ip, country);
}

async function ip2countryIPv4(ip: string): Promise<string | null> {
	if (!geoip_db) return null;
	const ipNumber = ip4ToNumber(ip);
	const result = await geoip_db
		.prepare('SELECT country_iso_code FROM merged_ipv4_data WHERE network_start <= ?1 ORDER BY network_start DESC LIMIT 1;')
		.bind(ipNumber)
		.first<GeoIpResult>();
	return result?.country_iso_code ?? null;
}

async function ip2countryIPv6(ip: string): Promise<string | null> {
	if (!geoip_db) return null;
	const hexIp = ipv6ToHex(ip);
	const result = await geoip_db
		.prepare('SELECT country_iso_code FROM merged_ipv6_data WHERE network_start <= ?1 ORDER BY network_start DESC LIMIT 1;')
		.bind(hexIp)
		.first<GeoIpResult>();
	return result?.country_iso_code ?? null;
}

// ============================================================
// DNS Response Parser (A + AAAA Records)
// ============================================================

// DNS Record Types
const DNS_TYPE_A = 1;
const DNS_TYPE_AAAA = 28;

/**
 * Skip a DNS name (handles both compressed and uncompressed formats).
 * Returns the new offset after skipping the name.
 */
function skipDnsName(data: Uint8Array, offset: number): number {
	if ((data[offset] & 0xc0) === 0xc0) {
		return offset + 2; // Compressed name pointer
	}
	while (data[offset] !== 0) offset++;
	return offset + 1;
}

/**
 * Parse an A record (IPv4) from the DNS response.
 */
function parseARecord(data: Uint8Array, offset: number, ttl: number): DnsAnswer {
	const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
	return { type: 'A', ip, ttl };
}

/**
 * Parse an AAAA record (IPv6) from the DNS response.
 */
function parseAAAARecord(data: Uint8Array, offset: number, ttl: number): DnsAnswer {
	const parts: string[] = [];
	for (let j = 0; j < 8; j++) {
		const segment = (data[offset + j * 2] << 8) | data[offset + j * 2 + 1];
		parts.push(segment.toString(16));
	}
	return { type: 'AAAA', ip: parts.join(':'), ttl };
}

/**
 * Parse a single DNS answer record.
 * Returns { answer, newOffset } where answer may be null for unsupported record types.
 */
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

function parseDnsResponse(buffer: ArrayBuffer): DnsResponse {
	const data = new Uint8Array(buffer);
	let offset = 0;

	// Parse header (12 bytes)
	const id = (data[offset] << 8) | data[offset + 1];
	const flags = (data[offset + 2] << 8) | data[offset + 3];
	const qdCount = (data[offset + 4] << 8) | data[offset + 5];
	const anCount = (data[offset + 6] << 8) | data[offset + 7];
	const nsCount = (data[offset + 8] << 8) | data[offset + 9];
	const arCount = (data[offset + 10] << 8) | data[offset + 11];
	offset = 12;

	// Skip question section
	for (let i = 0; i < qdCount; i++) {
		offset = skipDnsName(data, offset) + 4; // Skip QTYPE(2) + QCLASS(2)
	}

	// Parse answer section
	const answers: DnsAnswer[] = [];
	for (let i = 0; i < anCount; i++) {
		const { answer, newOffset } = parseAnswerRecord(data, offset);
		if (answer) answers.push(answer);
		offset = newOffset;
	}

	// Calculate minimum TTL from all answers
	const minTtl = answers.length > 0 
		? Math.min(...answers.map(a => a.ttl))
		: 0;

	return { id, flags, qdCount, anCount, nsCount, arCount, answers, minTtl };
}
