/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of CONVOY's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://convoy.xyz
 *
 * ---
 *
 * Copyright (c) 2026 Justin Filip and individual contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "datum_pow.h"
#include "datum_utils.h"

static int datum_hex_nibble(const char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

bool datum_pow_decode_hex_exact(const char *hex, size_t out_len, unsigned char *out) {
	size_t i;
	if (!hex || !out) return false;
	for (i = 0; i < out_len; i++) {
		if (datum_hex_nibble(hex[i<<1]) < 0) return false;
		if (datum_hex_nibble(hex[(i<<1)+1]) < 0) return false;
		out[i] = hex2bin_uchar(&hex[i<<1]);
	}
	return hex[out_len<<1] == 0;
}

bool datum_pow_decode_u32_hex_exact(const char *hex, uint32_t *out) {
	uint32_t value = 0;
	int nibble;
	if (!hex || !out) return false;
	for (size_t i = 0; i < 8; i++) {
		nibble = datum_hex_nibble(hex[i]);
		if (nibble < 0) return false;
		value = (value << 4) | (uint32_t)nibble;
	}
	if (hex[8] != 0) return false;
	*out = value;
	return true;
}

bool datum_blake2b_time_on_wire(uint32_t *out, uint64_t ntime, uint64_t offset, uint8_t flags) {
	if (!out) return false;
	if (ntime > UINT32_MAX) return false;
	if (!(flags & DATUM_BLAKE2B_USE_TIME_OFFSET)) {
		*out = (uint32_t)ntime;
		return true;
	}
	if (offset > UINT32_MAX) return false;
	// Consensus derives the wire time with WrappingSubtract (Knots
	// src/util/overflow.h, used by CBlockHeader::GetTimeOnWire), so an offset
	// larger than nTime wraps modulo 2^32 rather than being rejected. The node
	// adds it back the same way on deserialization, so the round trip holds.
	*out = (uint32_t)ntime - (uint32_t)offset;
	return true;
}

uint32_t datum_blake2b_share_ntime(uint32_t time_on_wire, const unsigned char *ntime8, uint8_t flags) {
	uint32_t offset;
	if (!(flags & DATUM_BLAKE2B_USE_TIME_OFFSET) || !ntime8) return time_on_wire;
	// Bytes 0-3 of the hasher's time field go into the header as
	// m_time_offset (see datum_blake2b_serialize_block_header), and the node
	// adds them back to the wire time on deserialization, modulo 2^32.
	offset = (uint32_t)ntime8[0] | ((uint32_t)ntime8[1] << 8) | ((uint32_t)ntime8[2] << 16) | ((uint32_t)ntime8[3] << 24);
	return time_on_wire + offset;
}

static void datum_u256_shr(unsigned char *n, unsigned int bits) {
	const unsigned int byte_shift = bits / 8;
	const unsigned int bit_shift = bits % 8;
	int i;
	if (byte_shift) {
		memmove(n, n + byte_shift, 32 - byte_shift);
		memset(n + 32 - byte_shift, 0, byte_shift);
	}
	if (!bit_shift) return;
	for(i=0;i<31;i++) {
		n[i] = (unsigned char)((n[i] >> bit_shift) | (n[i + 1] << (8 - bit_shift)));
	}
	n[31] = (unsigned char)(n[31] >> bit_shift);
}

bool datum_blake2b_share_target(unsigned char *target, unsigned int bits) {
	if (!target || bits >= 224) return false;
	memset(target, 0xff, 28);
	memset(target + 28, 0, 4);
	if (bits) datum_u256_shr(target, bits);
	return true;
}

uint32_t datum_blake2b_share_nbits(unsigned int bits) {
	unsigned char target[32];
	unsigned int size = sizeof(target);
	uint32_t mantissa = 0;
	
	if (!datum_blake2b_share_target(target, bits)) return 0;
	while (size && !target[size - 1]) size--;
	if (size <= 3) {
		for (unsigned int i = 0; i < size; i++) {
			mantissa |= (uint32_t)target[i] << (8 * i);
		}
		mantissa <<= 8 * (3 - size);
	} else {
		mantissa = (uint32_t)target[size - 3] |
			((uint32_t)target[size - 2] << 8) |
			((uint32_t)target[size - 1] << 16);
	}
	if (mantissa & UINT32_C(0x00800000)) {
		mantissa >>= 8;
		size++;
	}
	// Compact encoding truncates toward a harder target. This is the closest
	// representable value that cannot classify work below Gateway's accepted
	// share target as satisfying the synthetic network target.
	return (size << 24) | (mantissa & UINT32_C(0x007fffff));
}

int datum_blake2b_format_stratum_difficulty(char *out, size_t out_size, uint64_t n) {
	if (!out || !out_size) return -1;
	int len = snprintf(out, out_size, "%.20Lf", datum_pdiff_to_bdiff(n));
	if (len < 0 || (size_t)len >= out_size) return -1;
	while (len > 0 && out[len - 1] == '0') out[--len] = '\0';
	if (len > 0 && out[len - 1] == '.') out[--len] = '\0';
	return len;
}

long double datum_blake2b_accounting_difficulty(long double x) {
	uint64_t xm1;
	if (x <= 1.0L) return 1.0L;
	if (x >= 9223372036854775808.0L) return (long double)UINT64_MAX;
	xm1 = (uint64_t)(x - 1.0L);
	if (!xm1) return 1.0L;
	return (long double)(1ULL << (64 - __builtin_clzll(xm1)));
}

bool datum_blake2b_256(unsigned char *out, const unsigned char *in, size_t len) {
	if (!out || (!in && len)) return false;
	return crypto_generichash_blake2b(out, 32, in, len, NULL, 0) == 0;
}

static void datum_reverse32(unsigned char *out, const unsigned char *in) {
	int i;
	for(i=0;i<32;i++) {
		out[i] = in[31 - i];
	}
}

static bool datum_xor_key_is_null(const unsigned char *xor_key) {
	static const unsigned char z[16] = {0};
	return !memcmp(xor_key, z, 16);
}

static void datum_sha256_tagged(unsigned char *out, const char *tag, const unsigned char *data, size_t len) {
	unsigned char taghash[32];
	crypto_hash_sha256_state st;
	crypto_hash_sha256(taghash, (const unsigned char *)tag, strlen(tag));
	crypto_hash_sha256_init(&st);
	crypto_hash_sha256_update(&st, taghash, 32);
	crypto_hash_sha256_update(&st, taghash, 32);
	if (data && len) {
		crypto_hash_sha256_update(&st, data, len);
	}
	crypto_hash_sha256_final(&st, out);
}

bool datum_blake2b_xor_key_hash(unsigned char *out, const unsigned char *xor_key) {
	if (!out || !xor_key) return false;
	datum_sha256_tagged(out, "Bitcoin block hash PoW XOR key", xor_key, 16);
	return true;
}

bool datum_blake2b_xor_key_matches_hash(
	const unsigned char *expected, const unsigned char *xor_key) {
	unsigned char actual[32];
	return expected && datum_blake2b_xor_key_hash(actual, xor_key) &&
		sodium_memcmp(actual, expected, sizeof(actual)) == 0;
}

static void datum_blake2b_xor_key_mask(unsigned char *mask, const unsigned char *xor_key, uint8_t clear_bits) {
	unsigned int clear_bytes;
	unsigned int rem;
	memset(mask, 0, 32);
	if (datum_xor_key_is_null(xor_key)) return;
	datum_sha256_tagged(mask, "Bitcoin block hash PoW XOR mask", xor_key, 16);
	clear_bytes = clear_bits / 8;
	rem = clear_bits % 8;
	if (clear_bytes) {
		memset(mask, 0, clear_bytes);
	}
	if (clear_bytes < 32) {
		mask[clear_bytes] &= (unsigned char)(0xffU >> rem);
	}
}

void datum_blake2b_coinb1(unsigned char *out, const unsigned char *commitment) {
	memset(out, 0, 3);
	memcpy(out + 3, commitment, 32);
	memset(out + 35, 0, 4);
}

void datum_blake2b_prevblock_hidden(unsigned char *out, const unsigned char *prevhash) {
	unsigned char ordered[32];
	datum_reverse32(ordered, prevhash);
	datum_sha256_tagged(out, "Bitcoin prevblock header, hashed", ordered, 32);
	memset(out, 0, 6);
}

void datum_blake2b_build_work_header_from_hidden(
	unsigned char *work, const unsigned char *prevhash_hidden,
	const unsigned char *nonce, const unsigned char *ntime,
	const unsigned char *root
) {
	memcpy(work, prevhash_hidden, 32);
	memcpy(work + 32, nonce, 8);
	memcpy(work + 40, ntime, 8);
	memcpy(work + 48, root, 32);
}

void datum_blake2b_build_work_header(unsigned char *work, const unsigned char *prevhash, const unsigned char *nonce, const unsigned char *ntime, const unsigned char *root) {
	unsigned char prevhash_hidden[32];
	datum_blake2b_prevblock_hidden(prevhash_hidden, prevhash);
	datum_blake2b_build_work_header_from_hidden(work, prevhash_hidden, nonce, ntime, root);
}

bool datum_blake2b_header_commitment_from_key_hash(
	unsigned char *commitment,
	uint32_t version,
	const unsigned char *prevhash,
	uint32_t height,
	const unsigned char *merkle,
	uint32_t time_on_wire,
	uint32_t nbits,
	uint32_t txcount,
	uint8_t flags,
	uint8_t xor_key_mask_clear_bits,
	const unsigned char *xor_key_hash,
	const unsigned char *rhs
) {
	unsigned char h1_payload[119];
	unsigned char h1_hash[32];
	unsigned char h2_payload[96];
	int o = 0;

	// Matches Knots CBlockHeader::GetHash H1 (119 bytes) + H2 merge-mining hook.
	// H1 version is the wire version, including header-v2 bit 0x80000000 (RC1+).
	if (!commitment || !prevhash || !merkle || !xor_key_hash || !rhs) return false;

	pk_u32le(h1_payload, o, version | UINT32_C(0x80000000)); o += 4;
	datum_reverse32(h1_payload + o, prevhash); o += 32;
	pk_u32le(h1_payload, o, height); o += 4;
	memcpy(h1_payload + o, merkle, 32); o += 32;
	pk_u32le(h1_payload, o, time_on_wire); o += 4;
	h1_payload[o++] = 0;
	pk_u32le(h1_payload, o, nbits); o += 4;
	pk_u32le(h1_payload, o, txcount); o += 4;
	h1_payload[o++] = flags;
	h1_payload[o++] = xor_key_mask_clear_bits;
	memcpy(h1_payload + o, xor_key_hash, 32); o += 32;
	if (o != (int)sizeof(h1_payload)) return false;

	datum_sha256_tagged(h1_hash, "Bitcoin block header 1", h1_payload, sizeof(h1_payload));

	memcpy(h2_payload, h1_hash, 32);
	memset(h2_payload + 32, 0, 32);
	memcpy(h2_payload + 64, rhs, 32);
	datum_sha256_tagged(commitment, "Merge-mining hook", h2_payload, sizeof(h2_payload));
	return true;
}

bool datum_blake2b_header_commitment(
	unsigned char *commitment, uint32_t version, const unsigned char *prevhash,
	uint32_t height, const unsigned char *merkle, uint32_t time_on_wire,
	uint32_t nbits, uint32_t txcount, uint8_t flags,
	uint8_t xor_key_mask_clear_bits, const unsigned char *xor_key,
	const unsigned char *rhs) {
	unsigned char xor_key_hash[32];
	return datum_blake2b_xor_key_hash(xor_key_hash, xor_key) &&
		datum_blake2b_header_commitment_from_key_hash(commitment, version,
			prevhash, height, merkle, time_on_wire, nbits, txcount, flags,
			xor_key_mask_clear_bits, xor_key_hash, rhs);
}

uint8_t datum_blake2b_abw_clear_bits(uint8_t target_pot) {
	const unsigned bits = DATUM_BLAKE2B_ABW_SHARE_TARGET_BASE_BITS + target_pot;
	return (uint8_t)(bits > 255 ? 255 : bits);
}

bool datum_blake2b_work_root(unsigned char *root, const unsigned char *commitment, const unsigned char *extranonce) {
	unsigned char leaf[52];
	if (!root || !commitment || !extranonce) return false;
	leaf[0] = 0;
	datum_blake2b_coinb1(leaf + 1, commitment);
	memcpy(leaf + 40, extranonce, 12);
	return datum_blake2b_256(root, leaf, sizeof(leaf));
}

bool datum_blake2b_pow_hash_le(unsigned char *hash_le, const unsigned char *work, const unsigned char *xor_key, uint8_t xor_key_mask_clear_bits) {
	unsigned char hash[32];
	int i;
	if (!hash_le || !work || !xor_key) return false;
	if (!datum_blake2b_256(hash, work, 80)) return false;
	for(i=0;i<32;i++) hash_le[31 - i] = hash[i];
	return datum_blake2b_apply_xor_mask_le(
		hash_le, hash_le, xor_key, xor_key_mask_clear_bits);
}

bool datum_blake2b_apply_xor_mask_le(unsigned char *out,
	const unsigned char *raw_hash, const unsigned char *xor_key,
	uint8_t xor_key_mask_clear_bits) {
	unsigned char mask[32];
	if (!out || !raw_hash || !xor_key) return false;
	datum_blake2b_xor_key_mask(mask, xor_key, xor_key_mask_clear_bits);
	for(int i=0;i<32;i++) out[i] = raw_hash[i] ^ mask[31 - i];
	return true;
}

void datum_blake2b_serialize_block_header(
	unsigned char *header,
	uint32_t version,
	const unsigned char *prevhash,
	const unsigned char *merkle,
	uint32_t time_on_wire,
	uint32_t nbits,
	const unsigned char *nonce,
	const unsigned char *ntime,
	const unsigned char *extranonce,
	uint16_t txcount,
	uint8_t flags,
	uint8_t xor_key_mask_clear_bits,
	const unsigned char *xor_key,
	uint32_t height,
	const unsigned char *rhs
) {
	pk_u32le(header, 0, version | UINT32_C(0x80000000));
	memcpy(header + 4, prevhash, 32);
	memcpy(header + 36, merkle, 32);
	pk_u32le(header, 68, time_on_wire);
	pk_u32le(header, 72, nbits);
	memcpy(header + 76, nonce, 8);
	memcpy(header + 84, ntime + 4, 4);
	memset(header + 88, 0, 4);
	memcpy(header + 92, extranonce, 12);
	memcpy(header + 104, ntime, 4);
	pk_u16le(header, 108, txcount);
	header[110] = flags;
	header[DATUM_BLAKE2B_HEADER_XOR_CLEAR_BITS_OFFSET] = xor_key_mask_clear_bits;
	memcpy(header + DATUM_BLAKE2B_HEADER_XOR_KEY_OFFSET, xor_key, 16);
	pk_u32le(header, 128, height);
	memcpy(header + 132, rhs, 32);
}
