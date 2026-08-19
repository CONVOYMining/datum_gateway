/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
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

#ifndef _DATUM_POW_H_
#define _DATUM_POW_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DATUM_BLAKE2B_BLOCK_HEADER_SIZE 164
#define DATUM_BLAKE2B_USE_TIME_OFFSET 4

#define DATUM_POW_BLAKE2B 1
#define DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET 0x01
#define DATUM_POW_FLAG_BLAKE2B 0x08

bool datum_pow_decode_hex_exact(const char *hex, size_t out_len, unsigned char *out);

bool datum_blake2b_time_on_wire(uint32_t *out, uint64_t ntime, uint64_t offset, uint8_t flags);
bool datum_blake2b_share_target(unsigned char *target, unsigned int bits);
long double datum_blake2b_sia_difficulty(uint64_t n);
long double datum_blake2b_accounting_difficulty(long double x);

bool datum_blake2b_256(unsigned char *out, const unsigned char *in, size_t len);
void datum_blake2b_sia_coinb1(unsigned char *out, const unsigned char *commitment);
void datum_blake2b_sia_prevhash(unsigned char *out, const unsigned char *prevhash);
void datum_blake2b_build_work_header(unsigned char *work, const unsigned char *prevhash, const unsigned char *nonce, const unsigned char *ntime, const unsigned char *root);

bool datum_blake2b_header_commitment(
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
	const unsigned char *xor_key,
	const unsigned char *rhs
);
bool datum_blake2b_work_root(unsigned char *root, const unsigned char *commitment, const unsigned char *extranonce);
bool datum_blake2b_pow_hash_le(unsigned char *hash_le, const unsigned char *work, const unsigned char *xor_key, uint8_t xor_key_mask_clear_bits);
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
);

#endif
