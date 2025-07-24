import { serve } from "https://deno.land/std@0.220.0/http/server.ts";

// Types
interface FastlyIPList {
    addresses: string[];
    ipv6_addresses: string[];
}

interface CIDRInfo {
    net: string;
    originalCIDR: string;
}

interface IPAssociation {
    entry: string;
    reason: string;
}

interface Config {
    timeout: number;
    retries: number;
    retryDelay: number;
    concurrency: number;
}

interface Proxy {
    name: string;
    server: string;
}

interface Response {
    status: string;
    message?: any;
}

interface ResponseWithIP extends Response {
    ip?: string;
}

interface StatusCountMsg {
    timestamp: number;
    count: number;
}

interface RSSFeed {
    rss: {
        channel: {
            item: Array<{
                title: string;
                description: string;
            }>;
        };
    };
}

// Global variables
let fastlyCIDRs: string[] = [];
let riskySingleIPs = new Map<string, boolean>();
let riskyCIDRInfo: CIDRInfo[] = [];
let reasonMap = new Map<string, string>();
let ipCache = new Map<string, { timestamp: number; entries: string[] }>();

const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const cidrRegex = /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

const localProxies = [
    "10.42.0.0/8",
    "10.0.0.0/16",
    "172.16.0.0/12",
    "fc00::/7"
];

const ipListAPIs = [
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "https://check.torproject.org/exit-addresses",
    "https://www.dan.me.uk/torlist/",
    "https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.txt",
    "https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1",
    "https://check.torproject.org/torbulkexitlist",
    "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset",
    "https://blocklist.greensnow.co/greensnow.txt",
    "https://checktor.483300.xyz/exit-addresses",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/8.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/7.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/4.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/3.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/2.txt",
];

const config: Config = {
    timeout: 10000,
    retries: 3,
    retryDelay: 2000,
    concurrency: 10
};

// Utility functions
function generateUUID(): string {
    return crypto.randomUUID();
}

function isValidIP(ip: string): boolean {
    // IPv4 validation
    if (ipRegex.test(ip)) {
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    // IPv6 validation (basic)
    if (ip.includes(':')) {
        const parts = ip.split(':');
        if (parts.length > 8) return false;
        return parts.every(part => {
            if (part === '') return true; // for ::
            return /^[0-9a-fA-F]{0,4}$/.test(part);
        });
    }

    return false;
}

function isIPAddress(s: string): boolean {
    return isValidIP(s);
}

function isBogonOrPrivateIP(ip: string): boolean {
    if (!isValidIP(ip)) return false;

    const privateIPBlocks = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16"
    ];

    const bogonIPBlocks = [
        "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24",
        "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32"
    ];

    const allBlocks = [...privateIPBlocks, ...bogonIPBlocks];

    for (const cidr of allBlocks) {
        if (isIPInCIDR(ip, cidr)) {
            return true;
        }
    }
    return false;
}

function isIPInCIDR(ip: string, cidr: string): boolean {
    try {
        const [network, prefixStr] = cidr.split('/');
        const prefix = parseInt(prefixStr, 10);

        if (ip.includes(':') || network.includes(':')) {
            // IPv6 - simplified check
            return false; // Skip IPv6 for now
        }

        const ipNum = ipToNumber(ip);
        const networkNum = ipToNumber(network);
        const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;

        return (ipNum & mask) === (networkNum & mask);
    } catch {
        return false;
    }
}

function ipToNumber(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isIPInFastlyCIDR(ip: string): boolean {
    return fastlyCIDRs.some(cidr => isIPInCIDR(ip, cidr));
}

function extractIPFromRequest(req: Request): string {
    const forwardedFor = req.headers.get('x-forwarded-for');
    const realIP = req.headers.get('x-real-ip');
    const cfConnectingIP = req.headers.get('cf-connecting-ip');
    const fastlyClientIP = req.headers.get('fastly-client-ip');

    // Try different headers in order of preference
    if (cfConnectingIP && isIPAddress(cfConnectingIP)) return cfConnectingIP;
    if (fastlyClientIP && isIPAddress(fastlyClientIP)) return fastlyClientIP;
    if (realIP && isIPAddress(realIP)) return realIP;
    if (forwardedFor) {
        const firstIP = forwardedFor.split(',')[0].trim();
        if (isIPAddress(firstIP)) return firstIP;
    }

    return '127.0.0.1'; // fallback
}

function getRiskStatusAndReason(ip: string): [boolean, string] {
    // Check single IPs
    if (riskySingleIPs.has(ip)) {
        const reason = reasonMap.get(ip) || "IP found in risk database (direct match).";
        return [true, reason];
    }

    // Check CIDR ranges
    for (const cidrEntry of riskyCIDRInfo) {
        if (isIPInCIDR(ip, cidrEntry.originalCIDR)) {
            const reason = reasonMap.get(cidrEntry.originalCIDR) ||
                `IP within risky CIDR ${cidrEntry.originalCIDR}.`;
            return [true, reason];
        }
    }

    return [false, ""];
}

function processLoadedEntries(entries: string[], reasonsForEntries: Map<string, string>) {
    const localSingleIPs = new Map<string, boolean>();
    const localCIDRInfo: CIDRInfo[] = [];
    const localReasonMap = new Map<string, string>();

    for (const entry of entries) {
        if (!entry) continue;

        if (cidrRegex.test(entry)) {
            localCIDRInfo.push({ net: entry, originalCIDR: entry });
            const reason = reasonsForEntries.get(entry);
            if (reason) localReasonMap.set(entry, reason);
        } else if (ipRegex.test(entry)) {
            localSingleIPs.set(entry, true);
            const reason = reasonsForEntries.get(entry);
            if (reason) localReasonMap.set(entry, reason);
        }
    }

    riskySingleIPs = localSingleIPs;
    riskyCIDRInfo = localCIDRInfo;
    reasonMap = localReasonMap;
}

// API fetching functions
async function fetchWithRetry(url: string, config: Config): Promise<Response | null> {
    for (let attempt = 0; attempt < config.retries; attempt++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.timeout);

            const response = await fetch(url, {
                headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36' },
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            console.log(`Error fetching ${url} (attempt ${attempt + 1}/${config.retries}):`, error);
            if (attempt < config.retries - 1) {
                await new Promise(resolve => setTimeout(resolve, config.retryDelay * (attempt + 1)));
            }
        }
    }
    return null;
}

function getSourceIdentifier(rawURL: string): string {
    if (rawURL.includes('projecthoneypot.org')) return 'Project Honeypot';
    if (rawURL.includes('torproject.org')) return 'Tor Project';
    if (rawURL.includes('spamhaus.org')) return 'Spamhaus';
    if (rawURL.includes('cinsscore.com')) return 'CINS Score';
    if (rawURL.includes('blocklist.de')) return 'Blocklist.de';
    if (rawURL.includes('firehol/blocklist-ipsets/master/cybercrime.ipset')) return 'Firehol Cybercrime';
    if (rawURL.includes('firehol_level1.netset')) return 'Firehol Level 1';
    if (rawURL.includes('firehol_level2.netset')) return 'Firehol Level 2';
    if (rawURL.includes('firehol_level3.netset')) return 'Firehol Level 3';
    if (rawURL.includes('firehol_level4.netset')) return 'Firehol Level 4';
    if (rawURL.includes('greensnow.co')) return 'GreenSnow';
    if (rawURL.includes('X4BNet')) return 'X4BNet VPN/Datacenter';
    if (rawURL.includes('bruteforceblocker')) return 'BruteforceBlocker';
    if (rawURL.includes('dan.me.uk/torlist')) return 'Dan.me.uk Tor List';
    if (rawURL.includes('stamparm/ipsum')) {
        const match = rawURL.match(/levels\/(\d+)\.txt/);
        if (match) return `IPSum Level ${match[1]}`;
        return 'IPSum Wall of Shame';
    }

    try {
        return new URL(rawURL).hostname;
    } catch {
        return 'Unknown Source';
    }
}

// Simple XML parser for RSS (since external XML lib may cause issues)
function parseSimpleRSS(xmlText: string): { title: string; description: string }[] {
    const items: { title: string; description: string }[] = [];
    const itemRegex = /<item>(.*?)<\/item>/gs;
    const titleRegex = /<title><!\[CDATA\[(.*?)\]\]><\/title>/s;
    const descRegex = /<description><!\[CDATA\[(.*?)\]\]><\/description>/s;

    let match;
    while ((match = itemRegex.exec(xmlText)) !== null) {
        const itemContent = match[1];
        const titleMatch = titleRegex.exec(itemContent);
        const descMatch = descRegex.exec(itemContent);

        if (titleMatch && descMatch) {
            items.push({
                title: titleMatch[1],
                description: descMatch[1]
            });
        }
    }

    return items;
}

// Processors for different list formats
async function processProjectHoneypotRSS(body: string): Promise<IPAssociation[]> {
    const associations: IPAssociation[] = [];
    try {
        const items = parseSimpleRSS(body);

        for (const item of items) {
            if (item.title?.startsWith('IP:')) {
                const ipStr = item.title.replace('IP:', '').trim();
                if (ipRegex.test(ipStr)) {
                    const reason = `ProjectHoneypot: ${item.description?.trim() || ''}`;
                    associations.push({ entry: ipStr, reason });
                }
            }
        }
    } catch (error) {
        console.log('Error parsing ProjectHoneypot RSS:', error);
    }
    return associations;
}

function processSpamhausList(body: string): IPAssociation[] {
    const associations: IPAssociation[] = [];
    const lines = body.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith(';')) continue;

        const parts = trimmed.split(';', 2);
        const entry = parts[0].trim();

        if (ipRegex.test(entry) || cidrRegex.test(entry)) {
            let reason = 'Spamhaus DROP list';
            if (parts.length > 1 && parts[1].trim()) {
                reason += `: ${parts[1].trim()}`;
            }
            associations.push({ entry, reason });
        }
    }
    return associations;
}

function processTorBulkExitList(body: string): IPAssociation[] {
    const associations: IPAssociation[] = [];
    const lines = body.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        if (ipRegex.test(trimmed)) {
            associations.push({ entry: trimmed, reason: 'Tor Bulk Exit Node' });
        }
    }
    return associations;
}

function processBruteforceBlocker(body: string): IPAssociation[] {
    const associations: IPAssociation[] = [];
    const lines = body.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const fields = trimmed.split(/\s+/);
        if (fields.length > 0 && ipRegex.test(fields[0])) {
            let reason = 'Bruteforce Blocker list';
            if (fields.length > 1) {
                reason += `: ${fields.slice(1).join(' ')}`;
            }
            associations.push({ entry: fields[0], reason });
        }
    }
    return associations;
}

function processTorExitAddresses(body: string): IPAssociation[] {
    const associations: IPAssociation[] = [];
    const lines = body.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('ExitAddress')) {
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2 && ipRegex.test(parts[1])) {
                associations.push({ entry: parts[1], reason: 'Tor Exit Address' });
            }
        }
    }
    return associations;
}

function processFireholList(body: string, sourceID: string): IPAssociation[] {
    const associations: IPAssociation[] = [];
    const lines = body.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') ||
            trimmed.startsWith('Name:') || trimmed.startsWith('Type:') ||
            trimmed.startsWith('Maintainer:') || trimmed.startsWith('Version:')) {
            continue;
        }

        if (ipRegex.test(trimmed) || cidrRegex.test(trimmed)) {
            associations.push({ entry: trimmed, reason: `Firehol list: ${sourceID}` });
        }
    }
    return associations;
}

function processGeneralIPList(body: string, sourceID: string): IPAssociation[] {
    const associations: IPAssociation[] = [];
    const lines = body.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const fields = trimmed.split(/\s+/);
        if (fields.length > 0) {
            const entry = fields[0];
            if (ipRegex.test(entry) || cidrRegex.test(entry)) {
                const reason = `General blocklist: ${sourceID}`;
                associations.push({ entry, reason });
            }
        }
    }
    return associations;
}

async function fetchIPList(apiURL: string, config: Config): Promise<IPAssociation[]> {
    const sourceID = getSourceIdentifier(apiURL);
    const response = await fetchWithRetry(apiURL, config);

    if (!response || !response.ok) {
        console.log(`Failed to fetch IP list from ${apiURL}`);
        return [];
    }

    const body = await response.text();

    try {
        if (apiURL.includes('projecthoneypot.org')) {
            return await processProjectHoneypotRSS(body);
        } else if (apiURL.includes('spamhaus.org/drop')) {
            return processSpamhausList(body);
        } else if (apiURL.includes('torproject.org/torbulkexitlist')) {
            return processTorBulkExitList(body);
        } else if (apiURL.includes('bruteforceblocker')) {
            return processBruteforceBlocker(body);
        } else if (apiURL.includes('torproject.org/exit-addresses')) {
            return processTorExitAddresses(body);
        } else if (apiURL.includes('firehol')) {
            return processFireholList(body, sourceID);
        } else {
            return processGeneralIPList(body, sourceID);
        }
    } catch (error) {
        console.log(`Error processing ${apiURL}:`, error);
        return [];
    }
}

async function updateIPLists(config: Config) {
    console.log('Starting IP lists update...');

    const promises = ipListAPIs.map(url => fetchIPList(url, config));
    const results = await Promise.all(promises);

    const newEntries = new Set<string>();
    const newReasons = new Map<string, string>();

    for (const associations of results) {
        for (const assoc of associations) {
            if (assoc.entry) {
                newEntries.add(assoc.entry);
                if (assoc.reason) {
                    newReasons.set(assoc.entry, assoc.reason);
                }
            }
        }
    }

    if (newEntries.size > 0) {
        const entryList = Array.from(newEntries);
        processLoadedEntries(entryList, newReasons);

        // Cache the results
        ipCache.set('risky_ip_list_entries', {
            timestamp: Date.now(),
            entries: entryList
        });

        const count = riskySingleIPs.size + riskyCIDRInfo.length;
        const reasonCount = reasonMap.size;
        console.log(`Successfully updated risky IP lists: ${count} unique entries. Reason map entries: ${reasonCount}`);
    } else {
        console.log('Warning: No IP data obtained from any source. Lists not updated.');
    }
}

async function updateFastlyIPs() {
    try {
        const response = await fetch('https://api.fastly.com/public-ip-list');
        let ipList: FastlyIPList;

        if (response.ok) {
            ipList = await response.json();
            console.log('Fetched Fastly IPs from API');
        } else {
            // Fallback to hardcoded IPs
            ipList = {
                addresses: [
                    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
                    "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
                    "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
                    "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
                    "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
                    "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
                    "199.232.0.0/16"
                ],
                ipv6_addresses: [
                    "2a04:4e40::/32", "2a04:4e42::/32"
                ]
            };
            console.log('Using hardcoded Fastly IPs');
        }
        fastlyCIDRs = [...ipList.addresses, ...ipList.ipv6_addresses];

        console.log(`Updated fastlyCIDRs: ${fastlyCIDRs.length} entries`);
    } catch (error) {
        console.log('Error updating Fastly IPs:', error);
    }
}

// Cloudflare 列表内存存储
const cloudflareListMap = new Map<string, string>();

async function updateCloudflareList() {
    try {
        const [v4Response, v6Response] = await Promise.all([
            fetch('https://www.cloudflare.com/ips-v4'),
            fetch('https://www.cloudflare.com/ips-v6')
        ]);

        const v4Data = await v4Response.text();
        const v6Data = await v6Response.text();

        const lines = [...v4Data.split('\n'), ...v6Data.split('\n')]
            .map(l => l.trim())
            .filter(l => l !== '');

        // 存入内存 map
        cloudflareListMap.set('cloudflare', lines.join('\n'));
        console.log('Updated Cloudflare list (in memory)');
    } catch (error) {
        console.log('Cloudflare list update error:', error);
    }
}

// Fastly 列表内存存储
const fastlyListMap = new Map<string, string>();

async function updateFastlyList() {
    try {
        const response = await fetch('https://api.fastly.com/public-ip-list');
        const data = await response.json();
        const all = [...(data.addresses || []), ...(data.ipv6_addresses || [])];
        // 存入内存 map
        fastlyListMap.set('fastly', all.join('\n'));
        console.log('Updated Fastly list (in memory)');
    } catch (error) {
        console.log('Fastly list update error:', error);
    }
}

function processProxies(proxies: Proxy[]): Proxy[] {
    const nonRiskyProxies: Proxy[] = [];

    for (const proxy of proxies) {
        if (isIPAddress(proxy.server)) {
            if (isBogonOrPrivateIP(proxy.server)) {
                continue; // Skip bogon/private IPs
            }
            const [risky] = getRiskStatusAndReason(proxy.server);
            if (risky) {
                continue; // Skip risky IPs
            }
        }
        nonRiskyProxies.push(proxy);
    }

    return nonRiskyProxies;
}

function getAllowedDomains(): string[] {
    const env = Deno.env.get('ALLOWED_CORS');
    if (!env) {
        return ['catyuki.com', 'tzpro.xyz'];
    }
    return env.split(',').map(d => d.trim());
}

function isOriginAllowed(origin: string | null): boolean {
    if (!origin) return false;

    if (!origin.startsWith('https://')) {
        return false;
    }

    const allowedDomains = getAllowedDomains();
    for (const domain of allowedDomains) {
        if (origin === `https://${domain}` || origin.endsWith(`.${domain}`)) {
            return true;
        }
    }
    return false;
}

// HTTP handlers
async function handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // CORS headers
    const corsHeaders = new Headers({
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Origin, Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '43200'
    });

    const origin = req.headers.get('Origin');
    if (isOriginAllowed(origin)) {
        corsHeaders.set('Access-Control-Allow-Origin', origin!);
    }

    // Handle preflight
    if (method === 'OPTIONS') {
        return new Response(null, { status: 200, headers: corsHeaders });
    }

    // Add correlation ID
    const correlationID = req.headers.get('X-Request-ID') || generateUUID();
    corsHeaders.set('X-Request-ID', correlationID);

    try {
        // Route handling
        if (path === '/filter-proxies' && method === 'POST') {
            const proxies: Proxy[] = await req.json();
            const nonRiskyProxies = processProxies(proxies);
            const filteredData = {
                filtered_count: proxies.length - nonRiskyProxies.length,
                proxies: nonRiskyProxies
            };

            return new Response(JSON.stringify({
                status: 'ok',
                message: filteredData
            }), {
                status: 200,
                headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
            });
        }

        if (path.startsWith('/api/v1/ip/')) {
            const ip = path.slice('/api/v1/ip/'.length);
            return handleIPCheck(ip, corsHeaders);
        }

        if (path === '/api/v1/ip') {
            const ip = extractIPFromRequest(req);
            return handleRequestIPCheck(ip, corsHeaders);
        }

        if (path === '/' && method === 'GET') {
            return new Response(JSON.stringify({
                message: "Welcome to the OpenAI API! Documentation is available at https://platform.openai.com/docs/api-reference"
            }), {
                status: 200,
                headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
            });
        }

        if (path === '/api/status') {
            const count = riskySingleIPs.size + riskyCIDRInfo.length;
            return new Response(JSON.stringify({
                status: 'ok',
                message: {
                    timestamp: Math.floor(Date.now() / 1000),
                    count
                }
            }), {
                status: 200,
                headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
            });
        }

        if (path.startsWith('/cdn/')) {
            const name = path.slice('/cdn/'.length);
            const allowed = ['edgeone', 'cloudflare', 'fastly', 'all'];

            if (!allowed.includes(name)) {
                return new Response(JSON.stringify({
                    status: 'Bad Request',
                    message: 'Available CDN lists: [edgeone, cloudflare, fastly, all]'
                }), {
                    status: 400,
                    headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
                });
            }

            try {
                if (name === 'cloudflare') {
                    // 直接从内存 map 读取
                    const content = cloudflareListMap.get('cloudflare') || '';
                    const pulledAt = new Date().toISOString().replace('T', ' ').substring(0, 19);
                    const headers = { ...Object.fromEntries(corsHeaders), 'Content-Type': 'text/plain', 'X-Pulled-At': pulledAt };
                    return new Response(content, {
                        status: 200,
                        headers
                    });
                } else if (name === 'fastly') {
                    // fastly 也从内存 map 读取
                    const content = fastlyListMap.get('fastly') || '';
                    const pulledAt = new Date().toISOString().replace('T', ' ').substring(0, 19);
                    const headers = { ...Object.fromEntries(corsHeaders), 'Content-Type': 'text/plain', 'X-Pulled-At': pulledAt };
                    return new Response(content, {
                        status: 200,
                        headers
                    });
                } else if (name === 'all') {
                    // 合并所有 CDN 的 CIDR 列表
                    const pulledAt = new Date().toISOString().replace('T', ' ').substring(0, 19);
                    let allContent = `# CDN CIDR Lists - Pulled at ${pulledAt}\n\n`;

                    // EdgeOne
                    try {
                        const edgeoneContent = await Deno.readTextFile('data/edgeone.txt');
                        allContent += '# EdgeOne\n';
                        allContent += edgeoneContent.trim() + '\n\n';
                    } catch {
                        allContent += '# EdgeOne\n# (file not found)\n\n';
                    }

                    // Cloudflare
                    const cloudflareContent = cloudflareListMap.get('cloudflare') || '';
                    allContent += '# Cloudflare\n';
                    allContent += cloudflareContent.trim() + '\n\n';

                    // Fastly
                    const fastlyContent = fastlyListMap.get('fastly') || '';
                    allContent += '# Fastly\n';
                    allContent += fastlyContent.trim() + '\n';

                    const headers = { ...Object.fromEntries(corsHeaders), 'Content-Type': 'text/plain', 'X-Pulled-At': Date.now().toString() };
                    return new Response(allContent, {
                        status: 200,
                        headers
                    });
                } else {
                    // 其它（如 edgeone）继续读文件
                    const filePath = `data/${name}.txt`;
                    const content = await Deno.readTextFile(filePath);
                    return new Response(content, {
                        status: 200,
                        headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'text/plain' }
                    });
                }
            } catch {
                return new Response(JSON.stringify({
                    status: 'error',
                    message: 'File read error'
                }), {
                    status: 500,
                    headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
                });
            }
        }

        // 404 for other routes
        return new Response(JSON.stringify({
            status: 'error',
            message: 'Not Found'
        }), {
            status: 404,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error('Request error:', error);
        return new Response(JSON.stringify({
            status: 'error',
            message: 'Internal Server Error'
        }), {
            status: 500,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });
    }
}

function handleIPCheck(ip: string, corsHeaders: Headers): Response {
    if (!isIPAddress(ip)) {
        return new Response(JSON.stringify({
            status: 'error',
            message: 'Invalid IP address format'
        }), {
            status: 400,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });
    }

    if (isBogonOrPrivateIP(ip)) {
        return new Response(JSON.stringify({
            status: 'error',
            message: 'This is a private or bogon IP address.'
        }), {
            status: 422,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });
    }

    const [risky, reason] = getRiskStatusAndReason(ip);
    const responseData = risky
        ? { status: 'banned', message: reason }
        : { status: 'ok', message: 'IP is not listed as risky.' };

    return new Response(JSON.stringify(responseData), {
        status: 200,
        headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
    });
}

function handleRequestIPCheck(ip: string, corsHeaders: Headers): Response {
    if (ip === '::1' || ip === '127.0.0.1') {
        return new Response(JSON.stringify({
            status: 'ok',
            message: 'Request from localhost.',
            ip
        }), {
            status: 200,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });
    }

    if (!isIPAddress(ip)) {
        return new Response(JSON.stringify({
            status: 'error',
            message: 'Invalid or unidentifiable IP address.',
            ip
        }), {
            status: 400,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });
    }

    if (isBogonOrPrivateIP(ip)) {
        return new Response(JSON.stringify({
            status: 'ok',
            message: 'Request from a private or bogon IP address.',
            ip
        }), {
            status: 200,
            headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
        });
    }

    const [risky, reason] = getRiskStatusAndReason(ip);
    const responseData = risky
        ? { status: 'banned', message: reason, ip }
        : { status: 'ok', message: 'IP is not listed as risky.', ip };

    return new Response(JSON.stringify(responseData), {
        status: 200,
        headers: { ...Object.fromEntries(corsHeaders), 'Content-Type': 'application/json' }
    });
}

// Background tasks
async function startPeriodicUpdates() {
    console.log('Starting periodic updates...');

    // Initial updates
    await updateFastlyIPs();
    await updateIPLists(config);
    await updateCloudflareList();
    await updateFastlyList();

    // Set up periodic updates
    setInterval(async () => {
        console.log('Running periodic Fastly IP update...');
        await updateFastlyIPs();
    }, 60 * 60 * 1000); // 1 hour

    setInterval(async () => {
        console.log('Running periodic IP lists update...');
        await updateIPLists(config);
    }, 60 * 60 * 1000); // 1 hour

    setInterval(async () => {
        console.log('Running periodic CDN lists update...');
        await updateCloudflareList();
        await updateFastlyList();
    }, 60 * 60 * 1000); // 1 hour
}

// Main function
async function main() {
    console.log('Starting Risky IP Filter server on :8080');

    // Initialize data directory
    try {
        await Deno.mkdir('data', { recursive: true });
        console.log('Data directory created/verified');
    } catch (error) {
        console.log('Data directory exists or creation failed:', error.message);
    }

    // Start background updates
    console.log('Initializing background tasks...');
    startPeriodicUpdates().catch(error => {
        console.error('Error in periodic updates:', error);
    });

    // Start HTTP server
    console.log('HTTP server starting...');
    await serve(handleRequest, {
        port: 8080,
        onListen: ({ port, hostname }) => {
            console.log(`🚀 Risky IP Filter server running on http://${hostname || 'localhost'}:${port}`);
        }
    });
}

// Error handler for the main function
if (import.meta.main) {
    try {
        await main();
    } catch (error) {
        console.error('Failed to start server:', error);
        Deno.exit(1);
    }
}