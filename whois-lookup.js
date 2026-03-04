'use strict';

const net = require('net');
const url = require('url');

// WHOIS server list — sourced from the whois npm package (hjr265/node-whois)
const SERVERS = require('./whois-servers.json');

const DEFAULT_TIMEOUT = 10000; // 10 seconds
const DEFAULT_FOLLOW = 2;      // max referral hops

// Matches referral WHOIS server hints in WHOIS responses
const REFERRAL_REGEX = /(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server|refer):[^\S\n]*((?:r?whois|https?):\/\/)?([0-9A-Za-z.\-_]*(:\d+)?)/;

/**
 * Perform a raw WHOIS TCP lookup for the given address.
 * @param {string} addr  Domain name or IP address
 * @param {object} options  Optional settings: server, timeout, follow
 * @returns {Promise<string>}
 */
function lookupRaw(addr, options, _follow) {
  if (_follow === undefined) _follow = options.follow !== undefined ? options.follow : DEFAULT_FOLLOW;

  return new Promise((resolve, reject) => {
    let server = options.server ? parseServer(options.server) : null;

    if (!server) {
      if (net.isIP(addr) !== 0) {
        server = parseServer(SERVERS['_'] && SERVERS['_']['ip']);
      } else {
        let tld = '';
        try { tld = url.domainToASCII(addr); } catch (_) { tld = addr; }
        while (tld) {
          if (SERVERS[tld]) {
            server = parseServer(SERVERS[tld]);
            break;
          }
          const dotIdx = tld.indexOf('.');
          if (dotIdx === -1) break;
          tld = tld.slice(dotIdx + 1);
        }
      }
    }

    if (!server) {
      return reject(new Error('No WHOIS server is known for this kind of object'));
    }

    server.port = server.port || 43;
    server.query = server.query || '$addr\r\n';

    const socket = net.connect({ host: server.host, port: server.port });
    const timeout = options.timeout || DEFAULT_TIMEOUT;
    socket.setTimeout(timeout);

    let data = '';

    socket.on('connect', () => {
      socket.write(server.query.replace('$addr', addr));
    });
    socket.on('data', (chunk) => {
      data += chunk;
    });
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('WHOIS lookup timed out'));
    });
    socket.on('error', (err) => {
      reject(err);
    });
    socket.on('close', () => {
      if (_follow > 0) {
        const referral = extractReferral(data, server);
        if (referral) {
          return lookupRaw(addr, { ...options, server: referral }, _follow - 1)
            .then(resolve)
            .catch(reject);
        }
      }
      resolve(data);
    });
  });
}

function parseServer(server) {
  if (!server) return null;
  if (typeof server === 'string') {
    const [host, port] = server.split(':');
    return { host, port: port ? parseInt(port, 10) : undefined };
  }
  return { ...server };
}

function extractReferral(data, currentServer) {
  const match = data
    .replace(/\r/g, '')
    .match(REFERRAL_REGEX);
  if (!match) return null;
  const value = (match[3] || '').replace(/^[:\s]+/, '').replace(/^https?[:\/]+/, '');
  if (!value || value === currentServer.host) return null;
  return parseServer(value);
}

/**
 * Parse raw WHOIS text into a camelCase key-value object.
 * @param {string} rawData
 * @returns {object}
 */
function parseRaw(rawData) {
  const result = {};
  const lines = rawData.replace(/\r/g, '').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#') || trimmed.startsWith('>')) continue;
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;
    const rawKey = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();
    if (!rawKey || !value) continue;
    const key = toCamelCase(rawKey);
    if (!(key in result)) {
      result[key] = value;
    }
  }
  return result;
}

function toCamelCase(str) {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+([a-z0-9])/g, (_, char) => char.toUpperCase());
}

/**
 * Look up WHOIS info for a domain and return a parsed key-value object.
 * @param {string} domain
 * @param {object} [options]
 * @returns {Promise<object>}
 */
async function whoisLookup(domain, options) {
  const raw = await lookupRaw(domain, options || {});
  return parseRaw(raw);
}

module.exports = whoisLookup;
