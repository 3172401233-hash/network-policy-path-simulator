import { SimulationError, ERROR_CODES } from "./errors.js";

/**
 * Parse an IPv4 or IPv6 literal into a { value, family } pair.
 *
 * IPv4-mapped IPv6 addresses (e.g. ::ffff:10.0.0.1) are normalized to their
 * native IPv4 representation so they compare equal to plain IPv4 literals.
 *
 * @param {string} ip
 * @returns {{value: bigint, family: 4 | 6}}
 * @throws {SimulationError} INVALID_IP when the literal is not parseable.
 */
export function parseIp(ip) {
  if (typeof ip !== "string" || ip.length === 0) {
    throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IP address: ${String(ip)}`);
  }
  const trimmed = ip.trim();

  if (trimmed.includes(":")) {
    const mapped = parseMappedV4(trimmed);
    if (mapped) {
      return { value: mapped, family: 4 };
    }
    return { value: parseV6(trimmed), family: 6 };
  }
  return { value: parseV4(trimmed), family: 4 };
}

function parseV4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) {
    throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv4 address: ${value}`);
  }
  let result = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv4 address: ${value}`);
    }
    const octet = Number(part);
    if (octet > 255) {
      throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv4 address: ${value}`);
    }
    result = (result << 8n) | BigInt(octet);
  }
  return result;
}

function parseMappedV4(value) {
  const match = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (!match) {
    return null;
  }
  return parseV4(match[1]);
}

function parseV6(value) {
  let head = value;
  let tail = "";
  const doubleColon = value.indexOf("::");
  if (doubleColon !== -1) {
    if (value.indexOf("::", doubleColon + 1) !== -1) {
      throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv6 address: ${value}`);
    }
    head = value.slice(0, doubleColon);
    tail = value.slice(doubleColon + 2);
  }

  const headGroups = head.length === 0 ? [] : head.split(":");
  const tailGroups = tail.length === 0 ? [] : tail.split(":");
  const groups = [...headGroups, ...tailGroups];

  if (groups.some((group) => !/^[0-9a-fA-F]{1,4}$/.test(group))) {
    throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv6 address: ${value}`);
  }
  if (doubleColon === -1 && groups.length !== 8) {
    throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv6 address: ${value}`);
  }
  if (doubleColon !== -1 && groups.length > 7) {
    throw new SimulationError(ERROR_CODES.INVALID_IP, `Invalid IPv6 address: ${value}`);
  }

  const missing = 8 - groups.length;
  const full = [...headGroups, ...Array(missing).fill("0"), ...tailGroups];

  let result = 0n;
  for (const group of full) {
    result = (result << 16n) | BigInt(parseInt(group || "0", 16));
  }
  return result;
}

/**
 * Parse a CIDR string such as "10.0.0.0/8" or "fd00::/16".
 *
 * @param {string} cidr
 * @returns {{base: bigint, prefix: number, family: 4 | 6, maxPrefix: number}}
 * @throws {SimulationError} INVALID_CIDR on malformed input or family/prefix mismatch.
 */
export function parseCidr(cidr) {
  if (typeof cidr !== "string" || !cidr.includes("/")) {
    throw new SimulationError(ERROR_CODES.INVALID_CIDR, `Invalid CIDR: ${String(cidr)}`);
  }
  const [address, prefixText] = cidr.split("/");
  const { value, family } = parseIp(address);
  const maxPrefix = family === 4 ? 32 : 128;
  if (!/^\d+$/.test(prefixText)) {
    throw new SimulationError(ERROR_CODES.INVALID_CIDR, `Invalid CIDR prefix: ${cidr}`);
  }
  const prefix = Number(prefixText);
  if (prefix < 0 || prefix > maxPrefix) {
    throw new SimulationError(
      ERROR_CODES.INVALID_CIDR,
      `CIDR prefix /${prefix} is out of range for IPv${family}: ${cidr}`,
      { cidr },
    );
  }
  const bits = BigInt(maxPrefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << (bits - BigInt(prefix));
  const base = value & mask;
  return { base, prefix, family, maxPrefix };
}

/**
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
export function ipInCidr(ip, cidr) {
  const parsedIp = parseIp(ip);
  const network = parseCidr(cidr);
  if (parsedIp.family !== network.family) {
    return false;
  }
  const bits = BigInt(network.maxPrefix);
  const mask =
    network.prefix === 0 ? 0n : ((1n << BigInt(network.prefix)) - 1n) << (bits - BigInt(network.prefix));
  return (parsedIp.value & mask) === network.base;
}

/**
 * Evaluate an ipBlock peer: the address must fall inside `cidr` and outside
 * every entry in `except`. Different IP families simply do not match.
 *
 * @param {string} ip
 * @param {{cidr: string, except?: string[]}} block
 * @returns {boolean}
 */
export function matchesIpBlock(ip, block) {
  let inside;
  try {
    inside = ipInCidr(ip, block.cidr);
  } catch (error) {
    if (error instanceof SimulationError) {
      throw new SimulationError(
        ERROR_CODES.INVALID_CIDR,
        `ipBlock uses an invalid CIDR "${block.cidr}": ${error.message}`,
        { cidr: block.cidr },
      );
    }
    throw error;
  }
  if (!inside) {
    return false;
  }
  for (const exception of block.except ?? []) {
    if (ipInCidr(ip, exception)) {
      return false;
    }
  }
  return true;
}
