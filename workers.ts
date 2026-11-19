/**
 * Country-Aware DNS over HTTPS (DoH) Worker
 *
 * Features:
 * - IPv4 & IPv6 support
 * - L1 (Memory) + L2 (Cache API) caching, TTL aging, single-flight dedup
 * - Upstream failover (Cloudflare primary, Google secondary, staggered race)
 * - AAAA record parsing
 * - Best-effort per-source-IP rate limiting (free-tier friendly, in-memory)
 *
 * Free-tier constraints honored: no paid bindings (KV/DO/R2/Queues), bounded
 * in-memory structures, D1 reads only on cache miss, CPU work per request is
 * O(answers) packet walks — microseconds, far below the 10ms CPU budget.
 */

import {
	DNS_TYPE_A,
	DNS_TYPE_AAAA,
	InvalidDnsNameError,
	buildDnsQuery,
	combineQueryData,
	createOptRecord,
	extractHeaderAndQuestion,
	parseDnsQuery,
	parseDnsResponse,
	prepareCachedResponse,
	validateDnsQuery,
	validateDomainName,
} from './dns';
import { ip4ToNumber, ipv6ToHex, isIPv4, isIPv6, parseValidIp } from './ip';

// ============================================================
// Type Definitions
// ============================================================

interface Env {
	geolite2_country: D1Database;
	// Debug-only overrides (never set these in production): force the client
	// identity used for ECS/routing regardless of the actual request source.
	connectingIp?: string;
	connectingIpCountry?: string;
	// Config
	MEM_CACHE_MAX_SIZE?: string;
	CACHE_TTL_SECONDS?: string;
	DEBUG?: string;
	DEBUG_TOKEN?: string;
	COUNTRY_PRIORITY?: string;
	FORCE_AD?: string; // 'false' preserves the client's AD bit (default: force AD=1 upstream)
	RATE_LIMIT_PER_10S?: string; // requests per source IP per 10s window (default 100; 0 disables)
}

interface GeoIpResult {
	country_iso_code: string;
}

// ============================================================
// Global State & Cache
// ============================================================

let geoip_db: D1Database | null = null;
// L1 geo cache entries expire with the same TTL as L2 so daily data updates
// propagate without waiting for an isolate restart.
const MEM_CACHE = new Map<string, { country: string; expires: number }>();

// DNS Response Cache (L1 Memory)
const DNS_CACHE = new Map<string, { data: ArrayBuffer; expires: number; ttl: number }>();
const DNS_CACHE_MAX_SIZE = 5000;

// Single-flight: concurrent identical misses share one upstream fetch.
const IN_FLIGHT = new Map<string, Promise<ArrayBuffer>>();

// Defaults
let MEM_CACHE_MAX_SIZE = 10000;
let CACHE_TTL_SECONDS = 86400; // 24 hours
let DEBUG = false;
let FORCE_AD = true;
let RATE_LIMIT_PER_10S = 100;

// DNS Cache Config
const DNS_CACHE_CONFIG = {
	minTtl: 60, // Minimum 60 seconds
	maxTtl: 3600, // Maximum 1 hour
	negativeTtl: 300, // NXDOMAIN cache 5 minutes
	prefetchThreshold: 0.2, // Prefetch when remaining TTL < 20%
};

// Statistics (in-memory, resets on worker restart)
const STATS = {
	requests: { total: 0, doh: 0, json: 0, health: 0, debug: 0, rateLimited: 0 },
	cache: { memHits: 0, apiHits: 0, misses: 0 },
	dns: { cacheHits: 0, cacheMisses: 0, negativeCached: 0, prefetches: 0, upstreamFetches: 0 },
	errors: 0,
	startTime: Date.now(),
};

// D1 error cooldown: after a geo lookup failure, skip D1 for a short window
// instead of hammering a quota-exhausted / deleted / blocked database.
let d1_error_until = 0;
const D1_ERROR_COOLDOWN_MS = 30_000;

function log(...args: any[]) {
	if (DEBUG) {
		console.log(...args);
	}
}

// Country priority list for smart routing
// If response IP country matches any in this list, prefer it based on priority order
// Can be overridden via COUNTRY_PRIORITY env var (comma-separated)
let COUNTRY_PRIORITY: string[] = ['CN', 'HK', 'TW', 'JP', 'SG', 'US'];

// Selection priorities: lower wins. An answerless response must lose to any
// response that actually carries answers (NOERROR/empty happens in the wild).
const NOT_IN_PRIORITY_LIST = 999;
const NO_ANSWER_PRIORITY = 1000;

// Upstream DNS servers (Cloudflare first for internal network optimization)
const UPSTREAM_ENDPOINTS = [
	'https://1.1.1.1/dns-query', // Cloudflare (Primary)
	'https://dns.google/dns-query', // Google (Secondary)
];
const UPSTREAM_TIMEOUT_MS = 2500;
const UPSTREAM_RACE_DELAY_MS = 300; // backup starts only if primary is slow

// ============================================================
// Rate Limiting (best-effort, per isolate)
// ============================================================
// Token bucket per source IP: RATE_LIMIT_PER_10S capacity, refilled linearly
// over 10s. In-memory and per-isolate by design — zero cost on the free tier,
// no extra bindings. It raises the bar against quota-burn / upstream-hammering
// abuse; for hard guarantees add a Cloudflare WAF rate-limiting rule (see
// RUNBOOK). Map is capped; oldest entries are evicted when full.

const RATE_LIMITERS = new Map<string, { tokens: number; updated: number }>();
const RATE_LIMITER_MAX_ENTRIES = 10_000;
const RATE_LIMIT_WINDOW_MS = 10_000;

function rateLimitOk(sourceIp: string): boolean {
	if (RATE_LIMIT_PER_10S <= 0) return true;
	const now = Date.now();
	const capacity = RATE_LIMIT_PER_10S;
	let bucket = RATE_LIMITERS.get(sourceIp);
	if (bucket) {
		bucket.tokens = Math.min(capacity, bucket.tokens + ((now - bucket.updated) * capacity) / RATE_LIMIT_WINDOW_MS);
		bucket.updated = now;
		// LRU refresh so active IPs are not evicted first
		RATE_LIMITERS.delete(sourceIp);
		RATE_LIMITERS.set(sourceIp, bucket);
	} else {
		if (RATE_LIMITERS.size >= RATE_LIMITER_MAX_ENTRIES) {
			const oldest = RATE_LIMITERS.keys().next().value;
			if (oldest) RATE_LIMITERS.delete(oldest);
		}
		bucket = { tokens: capacity, updated: now };
		RATE_LIMITERS.set(sourceIp, bucket);
	}
	if (bucket.tokens < 1) return false;
	bucket.tokens -= 1;
	return true;
}

function rateLimitedResponse(): Response {
	STATS.requests.rateLimited++;
	return handleCors(
		new Response('Rate limit exceeded', {
			status: 429,
			headers: { 'Retry-After': '1', 'Content-Type': 'text/plain' },
		})
	);
}

/** Constant-time string comparison (length is not secret; content is). */
function timingSafeEqualStr(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= (a.codePointAt(i) ?? 0) ^ (b.codePointAt(i) ?? 0);
	}
	return diff === 0;
}

/** Per-request config refresh from env vars (module-level state). */
function initConfig(env: Env): void {
	if (env.MEM_CACHE_MAX_SIZE) MEM_CACHE_MAX_SIZE = Number.parseInt(env.MEM_CACHE_MAX_SIZE, 10) || 10000;
	if (env.CACHE_TTL_SECONDS) CACHE_TTL_SECONDS = Number.parseInt(env.CACHE_TTL_SECONDS, 10) || 86400;
	DEBUG = env.DEBUG === 'true';
	FORCE_AD = env.FORCE_AD !== 'false';
	if (env.RATE_LIMIT_PER_10S) {
		const n = Number.parseInt(env.RATE_LIMIT_PER_10S, 10);
		if (!Number.isNaN(n) && n >= 0) RATE_LIMIT_PER_10S = n;
	}
	if (env.COUNTRY_PRIORITY) {
		COUNTRY_PRIORITY = env.COUNTRY_PRIORITY.split(',').map((c) => c.trim().toUpperCase());
	}
}

// ============================================================
// Main Handler
// ============================================================

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		initConfig(env);

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

		// The actual request source (not the spoofable client-ip URL param)
		// keys the rate limiter.
		const sourceIp = request.headers.get('cf-connecting-ip') ?? 'unknown';

		if (path === '/resolve') {
			STATS.requests.json++;
			if (!rateLimitOk(sourceIp)) return rateLimitedResponse();
			return handleCors(await handleJsonDns(url, ctx));
		}

		if (path.startsWith('/debug/ip/')) {
			STATS.requests.debug++;
			// Token-gated (default closed): unauthenticated geo lookups are a
			// read-quota burn amplifier (5M rows_read/day is account-wide).
			const token = request.headers.get('x-debug-token');
			if (!env.DEBUG_TOKEN || !token || !timingSafeEqualStr(token, env.DEBUG_TOKEN)) {
				return handleCors(new Response('Not Found', { status: 404 }));
			}
			const ip = path.substring('/debug/ip/'.length);
			return handleCors(await handleDebugIp(ip, ctx));
		}

		// Legacy DoH endpoint
		STATS.requests.doh++;
		if (!rateLimitOk(sourceIp)) return rateLimitedResponse();
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
	headers.set('Access-Control-Allow-Headers', 'Content-Type, Accept, x-debug-token');
	headers.set('Access-Control-Max-Age', '86400');
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

/** Fresh DNS message response — never copy upstream headers (encoding/length
 * may describe a different body than the decoded buffer we hold). */
function dnsMessageResponse(buffer: ArrayBuffer): Response {
	return new Response(buffer, {
		headers: { 'Content-Type': 'application/dns-message' },
	});
}

// ============================================================
// Health Check Endpoint
// ============================================================

async function handleHealth(): Promise<Response> {
	// Real connectivity probe: binding-exists is not the same as queryable
	let database = 'disconnected';
	if (geoip_db) {
		try {
			await geoip_db.prepare('SELECT 1;').run();
			database = 'connected';
		} catch {
			database = 'error';
		}
	}
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
		database,
		d1Cooldown: Date.now() < d1_error_until,
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
			hitRate: totalCacheOps > 0 ? ((STATS.cache.memHits + STATS.cache.apiHits) / totalCacheOps).toFixed(3) : 'N/A',
		},
		dnsCache: {
			...STATS.dns,
			hitRate: totalDnsOps > 0 ? (STATS.dns.cacheHits / totalDnsOps).toFixed(3) : 'N/A',
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
	const type = (url.searchParams.get('type') || 'A').toUpperCase();

	if (!name) {
		return new Response(JSON.stringify({ error: 'Missing name parameter' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}
	if (type !== 'A' && type !== 'AAAA') {
		return new Response(JSON.stringify({ error: `Unsupported type '${type}': only A and AAAA are supported` }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	try {
		// Validate + canonicalize (strips trailing dot) before building anything
		const cleanName = validateDomainName(name);
		const queryData = buildDnsQuery(cleanName, type);

		// Query upstream (no ECS for the generic JSON API)
		const buffer = await queryDns(queryData, null, ctx);
		const dnsResponse = parseDnsResponse(buffer);

		// Format JSON response (Google DNS JSON API compatible).
		// Status is the RCODE (low 4 bits of flags) — NOT the opcode.
		const qtype = type === 'AAAA' ? DNS_TYPE_AAAA : DNS_TYPE_A;
		const jsonResponse: JsonDnsResponse = {
			Status: dnsResponse.flags & 0xf,
			TC: ((dnsResponse.flags >> 9) & 1) === 1,
			RD: ((dnsResponse.flags >> 8) & 1) === 1,
			RA: ((dnsResponse.flags >> 7) & 1) === 1,
			AD: ((dnsResponse.flags >> 5) & 1) === 1,
			CD: ((dnsResponse.flags >> 4) & 1) === 1,
			Question: [{ name: cleanName, type: qtype }],
			Answer: dnsResponse.answers.map((a) => ({
				name: cleanName,
				type: a.type === 'AAAA' ? DNS_TYPE_AAAA : DNS_TYPE_A,
				TTL: a.ttl, // Real TTL from the upstream answer
				data: a.ip,
			})),
		};

		return new Response(JSON.stringify(jsonResponse, null, 2), {
			headers: { 'Content-Type': 'application/json' },
		});
	} catch (err) {
		const error = err as Error;
		const status = err instanceof InvalidDnsNameError ? 400 : 500;
		return new Response(JSON.stringify({ error: error.message }), {
			status,
			headers: { 'Content-Type': 'application/json' },
		});
	}
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
	const entry = MEM_CACHE.get(ip);
	const inCache = !!entry && entry.expires > Date.now();

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

/**
 * One dual-resolution branch: query with the given ECS IP, then rank the
 * response by the country of its first answer. Module-level (not a closure
 * inside handleDoH) to keep cognitive complexity low.
 */
async function queryDnsWithIp(
	queryData: Uint8Array,
	ip: string | null,
	label: string,
	ctx: ExecutionContext
): Promise<{ response: Response; country: string | null; priority: number }> {
	const buffer = await queryDns(queryData, ip, ctx);
	const dnsResponse = parseDnsResponse(buffer);

	if (!dnsResponse.answers.length) {
		// Answerless responses rank BELOW any response carrying answers.
		return { response: dnsMessageResponse(buffer), country: null, priority: NO_ANSWER_PRIORITY };
	}

	const responseIpSample = dnsResponse.answers[0];
	const responseIpCountry = await ip2country(responseIpSample.ip, ctx);
	const priority = responseIpCountry ? COUNTRY_PRIORITY.indexOf(responseIpCountry) : -1;

	log(`${label} response: ${responseIpSample.ip}, Country: ${responseIpCountry}, Priority: ${priority}`);

	return {
		response: dnsMessageResponse(buffer),
		country: responseIpCountry,
		priority: priority >= 0 ? priority : NOT_IN_PRIORITY_LIST, // Not in list = lowest ranked answer
	};
}

async function handleDoH(request: Request, url: URL, env: Env, ctx: ExecutionContext): Promise<Response> {
	const params = url.pathname.substring(1).split('/');

	// Extract parameters (validate IP formats: an invalid value is dropped to
	// "no value" here instead of throwing inside createOptRecord and 500ing)
	const clientIp = parseValidIp(env.connectingIp || extractParam(params, 'client-ip') || request.headers.get('cf-connecting-ip'));
	const clientCountry = env.connectingIpCountry || extractParam(params, 'client-country') || request.headers.get('cf-ipcountry');

	// Alternative IP: from URL param, or fall back to client IP (for simplified URL)
	const alternativeIp = parseValidIp(parseAlternativeIp(params, clientIp)) ?? clientIp;

	// Parse DNS query
	const queryResult = await parseDnsQuery(request, url);
	if (queryResult instanceof Response) {
		return queryResult;
	}
	const queryData = queryResult;

	// Bounds-safe structural check before any parse loop touches the bytes
	const malformed = validateDnsQuery(queryData);
	if (malformed) {
		return malformed;
	}

	const queryUpstreamStart = Date.now();
	// allSettled: one failing branch must not discard the other's usable answer.
	// When both targets are the same IP the queries are identical (same cache
	// key / ECS) — share one promise instead of double-fetching upstream + D1.
	const clientPromise = queryDnsWithIp(queryData, clientIp, 'Client IP', ctx);
	const [clientSettled, altSettled] = await Promise.allSettled([
		clientPromise,
		alternativeIp === clientIp ? clientPromise : queryDnsWithIp(queryData, alternativeIp, 'Alt IP', ctx),
	]);
	const queryUpstreamEnd = Date.now();

	log(`Query Upstream Time: ${queryUpstreamEnd - queryUpstreamStart}ms`);

	const clientResult = clientSettled.status === 'fulfilled' ? clientSettled.value : null;
	const altResult = altSettled.status === 'fulfilled' ? altSettled.value : null;
	if (clientSettled.status === 'rejected') {
		STATS.errors++;
		log(`Client IP query failed: ${(clientSettled.reason as Error)?.message}`);
	}
	if (altSettled.status === 'rejected') {
		STATS.errors++;
		log(`Alt IP query failed: ${(altSettled.reason as Error)?.message}`);
	}
	if (!clientResult && !altResult) {
		return new Response('All query paths failed', { status: 502 });
	}

	// Client country exact match takes highest priority
	if (clientResult && clientCountry && clientResult.country === clientCountry) {
		log(`Selected: Client IP response (exact country match: ${clientCountry})`);
		return clientResult.response;
	}

	// Otherwise select by priority list; fall back to the surviving branch
	if (!altResult) return clientResult!.response;
	if (!clientResult) return altResult.response;
	if (clientResult.priority <= altResult.priority) {
		log(`Selected: Client IP response (priority: ${clientResult.priority} vs ${altResult.priority})`);
		return clientResult.response;
	} else {
		log(`Selected: Alt IP response (priority: ${altResult.priority} vs ${clientResult.priority})`);
		return altResult.response;
	}
}

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

// ============================================================
// DNS Query with Caching, Single-Flight and Upstream Failover
// ============================================================

/**
 * Check L1 memory cache: expired entries are purged; hits are served with the
 * current query's ID and TTLs aged by the time spent in cache.
 */
function checkL1Cache(cacheKey: string, queryData: Uint8Array, clientIp: string | null, ctx?: ExecutionContext): ArrayBuffer | null {
	const cachedEntry = DNS_CACHE.get(cacheKey);
	if (!cachedEntry) {
		return null;
	}
	if (cachedEntry.expires <= Date.now()) {
		DNS_CACHE.delete(cacheKey); // purge expired entries instead of letting them squat capacity
		return null;
	}

	// LRU: refresh position so hot entries are not evicted first
	DNS_CACHE.delete(cacheKey);
	DNS_CACHE.set(cacheKey, cachedEntry);

	STATS.dns.cacheHits++;
	log(`DNS Cache HIT (memory): ${cacheKey}`);

	const remainingMs = cachedEntry.expires - Date.now();

	// Check if we need to prefetch (remaining TTL < threshold)
	if (ctx) {
		const totalTtlMs = (cachedEntry.ttl || 300) * 1000;
		const remainingRatio = remainingMs / totalTtlMs;

		if (remainingRatio < DNS_CACHE_CONFIG.prefetchThreshold) {
			STATS.dns.prefetches++;
			log(`DNS Prefetch triggered: ${cacheKey}, remaining: ${Math.round(remainingRatio * 100)}%`);
			ctx.waitUntil(prefetchDns(queryData, clientIp, cacheKey));
		}
	}

	const elapsedSeconds = cachedEntry.ttl - remainingMs / 1000;
	return prepareCachedResponse(cachedEntry.data, queryData, elapsedSeconds);
}

/**
 * Check L2 Cache API and optionally warm up L1. Expired entries are treated
 * as a miss (never served stale).
 */
async function checkL2Cache(cacheKey: string, cacheUrl: Request, queryData: Uint8Array): Promise<ArrayBuffer | null> {
	const cache = caches.default;
	const cachedResponse = await cache.match(cacheUrl);
	if (!cachedResponse) {
		return null;
	}

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

	// Expired in L2: treat as a miss and revalidate upstream
	if (ttl <= 0) {
		log(`L2 entry expired, treating as miss: ${cacheKey}`);
		return null;
	}

	STATS.dns.cacheHits++;
	log(`DNS Cache HIT (cache api): ${cacheKey}`);

	// Age TTLs by time already spent in cache (X-Original-Ttl written on put;
	// entries written before that header existed are served unaged — fail open).
	let elapsedSeconds = 0;
	const originalTtlStr = cachedResponse.headers.get('X-Original-Ttl');
	if (originalTtlStr) {
		const originalTtl = Number.parseInt(originalTtlStr, 10);
		if (!Number.isNaN(originalTtl)) {
			elapsedSeconds = Math.max(0, originalTtl - ttl);
		}
	}

	updateDnsCache(cacheKey, buffer, ttl);
	return prepareCachedResponse(buffer, queryData, elapsedSeconds);
}

/**
 * Resolve a DNS query through L1 → L2 → single-flight upstream fetch.
 * Returns the raw DNS response buffer prepared for THIS query's ID.
 */
async function queryDns(queryData: Uint8Array, clientIp: string | null, ctx?: ExecutionContext): Promise<ArrayBuffer> {
	const cacheKey = generateDnsCacheKey(queryData, clientIp);

	// Check L1 Memory Cache
	const l1Result = checkL1Cache(cacheKey, queryData, clientIp, ctx);
	if (l1Result) return l1Result;

	// Check L2 Cache API
	const cacheUrl = new Request(`https://dns-cache.internal/${cacheKey}`);
	const l2Result = await checkL2Cache(cacheKey, cacheUrl, queryData);
	if (l2Result) return l2Result;

	STATS.dns.cacheMisses++;

	// Single-flight: concurrent identical misses share one upstream fetch
	// (saves upstream + D1 consumption; the free-tier request burst makes
	// thundering herds on hot names common).
	let inflight = IN_FLIGHT.get(cacheKey);
	if (!inflight) {
		inflight = fetchAndCache(queryData, clientIp, cacheKey, ctx).finally(() => {
			IN_FLIGHT.delete(cacheKey);
		});
		IN_FLIGHT.set(cacheKey, inflight);
	}
	const buffer = await inflight;

	// A shared in-flight response carries the first query's ID — rewrite to
	// this query's ID (elapsed 0: the buffer is fresh from upstream).
	return prepareCachedResponse(buffer, queryData, 0);
}

/**
 * Upstream fetch + cache population (the single-flight body).
 * Only NOERROR (rcode 0) and NXDOMAIN (rcode 3) are cached; SERVFAIL/REFUSED
 * and other error rcodes pass through uncached so the next request retries.
 */
async function fetchAndCache(queryData: Uint8Array, clientIp: string | null, cacheKey: string, ctx?: ExecutionContext): Promise<ArrayBuffer> {
	const buffer = await queryDnsUpstream(queryData, clientIp);
	const dnsResponse = parseDnsResponse(buffer);
	const rcode = dnsResponse.flags & 0xf;

	let ttl: number | null;
	if (rcode === 3) {
		// NXDOMAIN - use negative TTL
		ttl = DNS_CACHE_CONFIG.negativeTtl;
		STATS.dns.negativeCached++;
		log(`DNS NXDOMAIN cached: ${cacheKey}, TTL: ${ttl}s`);
	} else if (rcode === 0 && dnsResponse.answers.length > 0) {
		// Use real TTL from DNS response, bounded by config limits
		ttl = Math.min(Math.max(dnsResponse.minTtl, DNS_CACHE_CONFIG.minTtl), DNS_CACHE_CONFIG.maxTtl);
		log(`DNS Response cached: ${cacheKey}, realTTL: ${dnsResponse.minTtl}s, boundedTTL: ${ttl}s, answers: ${dnsResponse.answers.length}`);
	} else if (rcode === 0) {
		// NOERROR with no answers, minimal cache
		ttl = DNS_CACHE_CONFIG.minTtl;
	} else {
		// SERVFAIL / REFUSED / FORMERR / NOTIMPL: transient or query-specific —
		// caching would pin the failure for the whole TTL window.
		ttl = null;
		log(`DNS rcode ${rcode} not cached: ${cacheKey}`);
	}

	if (ttl !== null) {
		// Update L1 cache
		updateDnsCache(cacheKey, buffer, ttl);

		// Update L2 cache: register with the runtime so the put survives the
		// response being returned (bare fire-and-forget gets cancelled)
		if (ctx) {
			ctx.waitUntil(updateL2Cache(cacheKey, buffer, ttl));
		} else {
			await updateL2Cache(cacheKey, buffer, ttl);
		}
	}

	return buffer;
}

/**
 * Generate cache key from DNS query data and client IP prefix.
 * Domain is lowercased (DNS names are case-insensitive; DNS 0x20 clients
 * randomize case) and the IPv6 prefix uses the expanded hex form so different
 * textual representations of the same /48 share one entry.
 */
function generateDnsCacheKey(queryData: Uint8Array, clientIp: string | null): string {
	// Extract domain name and type from query (validateDnsQuery ran first)
	let offset = 12; // Skip header
	const domainParts: string[] = [];
	while (offset < queryData.length && queryData[offset] !== 0) {
		const len = queryData[offset];
		if (offset + 1 + len > queryData.length) break; // bounds guard
		const part = Array.from(queryData.slice(offset + 1, offset + 1 + len), (b) => String.fromCodePoint(b)).join('');
		domainParts.push(part);
		offset += len + 1;
	}
	const domain = domainParts.join('.').toLowerCase();
	offset++; // Skip null terminator
	const qtype = (queryData[offset] << 8) | queryData[offset + 1];

	// Get IP prefix for ECS-aware caching (matches the ECS prefix sent upstream)
	let ipPrefix = 'none';
	if (clientIp) {
		if (isIPv4(clientIp)) {
			// Use /24 prefix
			ipPrefix = clientIp.split('.').slice(0, 3).join('.');
		} else if (isIPv6(clientIp)) {
			// Use /48 prefix = first 12 hex chars of the expanded address
			ipPrefix = ipv6ToHex(clientIp).slice(0, 12);
		}
	}

	return `${domain}:${qtype}:${ipPrefix}`;
}

/**
 * Update DNS response cache with LRU eviction. An existing key only refreshes
 * its position — it never evicts an unrelated entry.
 */
function updateDnsCache(key: string, data: ArrayBuffer, ttlSeconds: number): void {
	if (!DNS_CACHE.has(key) && DNS_CACHE.size >= DNS_CACHE_MAX_SIZE) {
		const oldestKey = DNS_CACHE.keys().next().value;
		if (oldestKey) DNS_CACHE.delete(oldestKey);
	}
	// LRU: re-insert so an existing key moves to the newest position
	DNS_CACHE.delete(key);
	DNS_CACHE.set(key, {
		data,
		expires: Date.now() + ttlSeconds * 1000,
		ttl: ttlSeconds,
	});
}

/**
 * Update L2 Cache API with DNS response. X-Original-Ttl lets later hits age
 * the answer TTLs by the time spent in cache.
 */
async function updateL2Cache(cacheKey: string, buffer: ArrayBuffer, ttl: number): Promise<void> {
	const cache = caches.default;
	const cacheUrl = new Request(`https://dns-cache.internal/${cacheKey}`);
	const cacheResponse = new Response(buffer, {
		headers: {
			'Content-Type': 'application/dns-message',
			'Cache-Control': `max-age=${ttl}`,
			'X-Expires-At': `${Date.now() + ttl * 1000}`,
			'X-Original-Ttl': `${ttl}`,
		},
	});

	await cache.put(cacheUrl, cacheResponse).catch((err) => {
		STATS.errors++;
		log(`Cache put failed: ${err.message || err}`);
	});
}

/**
 * Prefetch DNS response in background before cache expires.
 */
async function prefetchDns(queryData: Uint8Array, clientIp: string | null, cacheKey: string): Promise<void> {
	try {
		const buffer = await queryDnsUpstream(queryData, clientIp);
		const dnsResponse = parseDnsResponse(buffer);
		const rcode = dnsResponse.flags & 0xf;

		let ttl: number | null = null;
		if (rcode === 0 && dnsResponse.answers.length > 0) {
			ttl = Math.min(Math.max(dnsResponse.minTtl, DNS_CACHE_CONFIG.minTtl), DNS_CACHE_CONFIG.maxTtl);
		} else if (rcode === 3) {
			ttl = DNS_CACHE_CONFIG.negativeTtl; // keep negative entries fresh too
		}
		if (ttl !== null) {
			updateDnsCache(cacheKey, buffer, ttl);
			await updateL2Cache(cacheKey, buffer, ttl);
			log(`DNS Prefetch completed: ${cacheKey}, TTL: ${ttl}s`);
		}
	} catch (err) {
		const error = err as Error;
		log(`DNS Prefetch failed: ${cacheKey}, error: ${error.message}`);
	}
}

/**
 * One upstream attempt in the staggered race. Module-level (not a closure)
 * to keep cognitive complexity low and the attempt logic independently readable.
 */
interface UpstreamRaceState {
	settled: boolean;
	controllers: AbortController[];
	lastServfail: ArrayBuffer | null;
}

async function fetchUpstreamAttempt(endpoint: string, body: Uint8Array, delayMs: number, state: UpstreamRaceState, start: number): Promise<ArrayBuffer> {
	if (delayMs > 0) {
		await new Promise((resolve) => setTimeout(resolve, delayMs));
	}
	if (state.settled) {
		throw new Error('race already settled'); // winner decided; skip the backup
	}
	const controller = new AbortController();
	state.controllers.push(controller);
	const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
	try {
		STATS.dns.upstreamFetches++;
		const response = await fetch(endpoint, {
			method: 'POST',
			headers: { 'Content-Type': 'application/dns-message' },
			body,
			signal: controller.signal,
		});
		if (!response.ok) {
			log(`Upstream ${endpoint} returned HTTP ${response.status}`);
			throw new Error(`HTTP ${response.status}`);
		}
		// Body read stays inside the abort window (no un-timed-out read)
		const buffer = await response.arrayBuffer();
		if (buffer.byteLength < 12) {
			throw new Error('short DNS response');
		}
		const rcode = new Uint8Array(buffer)[3] & 0xf;
		if (rcode === 2) {
			state.lastServfail = buffer; // keep as last-resort answer
			throw new Error('SERVFAIL'); // try the other upstream
		}
		log(`DNS Query via ${endpoint}: ${Date.now() - start}ms`);
		return buffer;
	} finally {
		clearTimeout(timeout);
	}
}

/**
 * Query upstream DNS servers: staggered race (primary first, backup after
 * UPSTREAM_RACE_DELAY_MS if the primary is slow), short per-attempt timeout,
 * failover on HTTP errors, timeouts, short bodies and SERVFAIL. If every
 * upstream SERVFAILs, the last response is returned (uncached) so the client
 * still receives a well-formed DNS answer.
 */
async function queryDnsUpstream(queryData: Uint8Array, clientIp: string | null): Promise<ArrayBuffer> {
	let newQueryData = queryData;
	if (clientIp) {
		const [headerAndQuestion] = extractHeaderAndQuestion(queryData);
		const optRecord = createOptRecord(clientIp);
		newQueryData = combineQueryData(headerAndQuestion, optRecord, FORCE_AD);
	}

	const start = Date.now();
	const state: UpstreamRaceState = { settled: false, controllers: [], lastServfail: null };

	try {
		return await Promise.any(
			UPSTREAM_ENDPOINTS.map((endpoint, i) => fetchUpstreamAttempt(endpoint, newQueryData, i * UPSTREAM_RACE_DELAY_MS, state, start))
		);
	} catch {
		if (state.lastServfail) {
			log('All upstreams returned SERVFAIL; serving last response uncached');
			return state.lastServfail;
		}
		STATS.errors++;
		throw new Error('All DNS upstreams failed');
	} finally {
		state.settled = true;
		for (const controller of state.controllers) {
			controller.abort(); // cancel losing/lingering fetches
		}
	}
}

// ============================================================
// IP to Country Lookup with Multi-Level Cache
// ============================================================

async function ip2country(ip: string, ctx: ExecutionContext): Promise<string | null> {
	// Validate IP format
	if (!isIPv4(ip) && !isIPv6(ip)) {
		return null;
	}

	// L1: Memory Cache (entries carry the same TTL as L2)
	const entry = MEM_CACHE.get(ip);
	if (entry && entry.expires > Date.now()) {
		// LRU: Refresh position
		MEM_CACHE.delete(ip);
		MEM_CACHE.set(ip, entry);
		STATS.cache.memHits++;
		return entry.country;
	}
	if (entry) {
		MEM_CACHE.delete(ip); // expired
	}

	// L2: Cache API
	const cache = caches.default;
	const cacheKey = new Request(`https://geoip.internal/${ip}`);
	const cachedResponse = await cache.match(cacheKey);

	if (cachedResponse) {
		const country = await cachedResponse.text();
		updateMemCache(ip, country);
		STATS.cache.apiHits++;
		return country;
	}

	// L3: D1 Database Query
	if (Date.now() < d1_error_until) {
		log('D1 in error cooldown, skipping geo lookup');
		return null;
	}
	STATS.cache.misses++;
	let country: string | null = null;
	try {
		country = isIPv4(ip) ? await ip2countryIPv4(ip) : await ip2countryIPv6(ip);
	} catch (err) {
		// D1 errors (read-quota exhaustion, DB deleted, timeout, ingest block)
		// degrade to "no geo info"; they must never 500 the whole request.
		const error = err as Error;
		STATS.errors++;
		d1_error_until = Date.now() + D1_ERROR_COOLDOWN_MS;
		log(`D1 geo lookup failed (cooldown ${D1_ERROR_COOLDOWN_MS}ms): ${error.message}`);
		return null;
	}

	if (country) {
		// Store in L1
		updateMemCache(ip, country);

		// Store in L2 (async, don't block response; failures are counted, not
		// left as unhandled rejections inside waitUntil)
		ctx.waitUntil(
			cache
				.put(
					cacheKey,
					new Response(country, {
						headers: { 'Cache-Control': `max-age=${CACHE_TTL_SECONDS}` },
					})
				)
				.catch((err) => {
					STATS.errors++;
					log(`Geoip cache put failed: ${err.message || err}`);
				})
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
	MEM_CACHE.set(ip, { country, expires: Date.now() + CACHE_TTL_SECONDS * 1000 });
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