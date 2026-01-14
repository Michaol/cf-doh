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
}

interface DnsAnswer {
    type: 'A' | 'AAAA';
    ip: string;
}

interface DnsResponse {
    id: number;
    flags: number;      // Reserved for future: DNSSEC validation
    qdCount: number;
    anCount: number;
    nsCount: number;    // Reserved for future: authority section parsing
    arCount: number;    // Reserved for future: additional section parsing
    answers: DnsAnswer[];
}

interface GeoIpResult {
    country_iso_code: string;
}

// ============================================================
// Global State & Cache
// ============================================================

let geoip_db: ReturnType<D1Database['withSession']> | null = null;
const MEM_CACHE = new Map<string, string>();
// Defaults
let MEM_CACHE_MAX_SIZE = 10000;
let CACHE_TTL_SECONDS = 86400; // 24 hours
let DEBUG = false;

function log(...args: any[]) {
    if (DEBUG) {
        console.log(...args);
    }
}

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

        // Initialize D1 with session for read replication
        geoip_db ??= env.geolite2_country.withSession();

        const url = new URL(request.url);
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
        async function queryDnsWithClientIp(): Promise<Response | null> {
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

            log(`Response Sample: ${responseIpSample.ip} (${responseIpSample.type}), Country: ${responseIpCountry}`);
            log(`Query Country Info Time: ${queryCountryInfoEnd - queryCountryInfoStart}ms`);

            if (clientCountry === responseIpCountry) {
                return new Response(buffer, response);
            }
            return null;
        }

        const queryUpstreamStart = Date.now();
        const [response, alternativeResponse] = await Promise.all([queryDnsWithClientIp(), queryDns(queryData, alternativeIp)]);
        const queryUpstreamEnd = Date.now();

        log(`Query Upstream Time: ${queryUpstreamEnd - queryUpstreamStart}ms`);

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

async function queryDns(queryData: Uint8Array, clientIp: string | null): Promise<Response> {
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
        if (ipParts.some(p => p < 0 || p > 255 || Number.isNaN(p))) {
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
    const emptyParts = parts.filter(p => p === '').length;
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
                const nonEmptyCount = parts.filter(p => p !== '').length;
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
function parseARecord(data: Uint8Array, offset: number): DnsAnswer {
    const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
    return { type: 'A', ip };
}

/**
 * Parse an AAAA record (IPv6) from the DNS response.
 */
function parseAAAARecord(data: Uint8Array, offset: number): DnsAnswer {
    const parts: string[] = [];
    for (let j = 0; j < 8; j++) {
        const segment = (data[offset + j * 2] << 8) | data[offset + j * 2 + 1];
        parts.push(segment.toString(16));
    }
    return { type: 'AAAA', ip: parts.join(':') };
}

/**
 * Parse a single DNS answer record.
 * Returns { answer, newOffset } where answer may be null for unsupported record types.
 */
function parseAnswerRecord(data: Uint8Array, offset: number): { answer: DnsAnswer | null; newOffset: number } {
    offset = skipDnsName(data, offset);

    const type = (data[offset] << 8) | data[offset + 1];
    const dataLen = (data[offset + 8] << 8) | data[offset + 9];
    offset += 10; // Skip type(2) + class(2) + TTL(4) + dataLen(2)

    let answer: DnsAnswer | null = null;
    if (type === DNS_TYPE_A && dataLen === 4) {
        answer = parseARecord(data, offset);
    } else if (type === DNS_TYPE_AAAA && dataLen === 16) {
        answer = parseAAAARecord(data, offset);
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

    return { id, flags, qdCount, anCount, nsCount, arCount, answers };
}
