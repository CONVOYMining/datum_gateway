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

#include <string.h>

#include "datum_pow.h"
#include "datum_utils.h"

static void datum_blake2b_share_ntime_tests(void) {
	/* What the node reads from a header built from a share, per case. The
	 * wire time is what the gateway used to bound, and it is only right
	 * when the offset flag is off. curtime is a real testnet4 block time. */
	const uint32_t curtime = 1787427585u;
	unsigned char ntime8[8], header[DATUM_BLAKE2B_BLOCK_HEADER_SIZE];
	unsigned char zero32[32] = {0}, nonce8[8] = {0}, en[12] = {0};
	uint32_t wire;
	
	/* Hasher time rolling: template offset 0, flag on, hasher rolls +10000. */
	pk_u32le(ntime8, 0, 10000); pk_u32le(ntime8, 4, curtime);
	datum_test(datum_blake2b_share_ntime(curtime, ntime8, DATUM_BLAKE2B_USE_TIME_OFFSET) == curtime + 10000);
	/* Rolling past 2^32 wraps to a time below curtime, as WrappingAdd does. */
	pk_u32le(ntime8, 0, 0xFFFFF000u);
	datum_test(datum_blake2b_share_ntime(curtime, ntime8, DATUM_BLAKE2B_USE_TIME_OFFSET) == curtime - 4096);
	/* Flag off: the offset bytes are not read as time. */
	pk_u32le(ntime8, 0, 10000);
	datum_test(datum_blake2b_share_ntime(curtime, ntime8, 0) == curtime);
	datum_test(datum_blake2b_share_ntime(curtime, NULL, DATUM_BLAKE2B_USE_TIME_OFFSET) == curtime);
	/* Template offset 600: wire is curtime - 600 and the node reads curtime. */
	datum_test(datum_blake2b_time_on_wire(&wire, curtime, 600, DATUM_BLAKE2B_USE_TIME_OFFSET));
	pk_u32le(ntime8, 0, 600);
	datum_test(wire == curtime - 600);
	datum_test(datum_blake2b_share_ntime(wire, ntime8, DATUM_BLAKE2B_USE_TIME_OFFSET) == curtime);
	/* The wrap vector from the time_on_wire tests round-trips to 599. */
	datum_test(datum_blake2b_time_on_wire(&wire, 599, 600, DATUM_BLAKE2B_USE_TIME_OFFSET));
	datum_test(wire == 4294967295u);
	datum_test(datum_blake2b_share_ntime(wire, ntime8, DATUM_BLAKE2B_USE_TIME_OFFSET) == 599);
	
	/* The helper reads the same bytes the serializer writes: wire time at
	 * 68-71 and the hasher's offset field at 104-107. */
	pk_u32le(ntime8, 0, 10000); pk_u32le(ntime8, 4, curtime);
	datum_blake2b_serialize_block_header(header, 0x20000000, zero32, zero32, curtime, 0x1d00ffff,
		nonce8, ntime8, en, 1, DATUM_BLAKE2B_USE_TIME_OFFSET, 0, zero32, 12345, zero32);
	datum_test(upk_u32le(header, 68) == curtime);
	datum_test(upk_u32le(header, 104) == 10000);
	datum_test(header[110] == DATUM_BLAKE2B_USE_TIME_OFFSET);
	datum_test(datum_blake2b_share_ntime(upk_u32le(header, 68), header + 104, header[110]) == curtime + 10000);
}

static void datum_blake2b_abw_pow_tests(void) {
	unsigned char xor_key[16];
	unsigned char key_hash[32];
	unsigned char legacy_commitment[32], committed_hash[32];
	unsigned char prevhash[32] = {0}, merkle[32] = {0}, rhs[32] = {0};
	unsigned char raw_hash[32], masked_hash[32];
	for (size_t i = 0; i < sizeof(xor_key); ++i) {
		xor_key[i] = (unsigned char)(i + 1);
	}
	for (size_t i = 0; i < sizeof(raw_hash); ++i) {
		raw_hash[i] = (unsigned char)(0x80 + i);
	}
	datum_test(datum_blake2b_xor_key_hash(key_hash, xor_key));
	datum_test(datum_blake2b_xor_key_matches_hash(key_hash, xor_key));
	datum_test(datum_blake2b_header_commitment(legacy_commitment,
		0x20000000, prevhash, 42, merkle, 1000, 0x1d00ffff, 1,
		0, 42, xor_key, rhs));
	datum_test(datum_blake2b_header_commitment_from_key_hash(committed_hash,
		0x20000000, prevhash, 42, merkle, 1000, 0x1d00ffff, 1,
		0, 42, key_hash, rhs));
	datum_test(!memcmp(legacy_commitment, committed_hash, 32));
	datum_test(datum_blake2b_abw_clear_bits(0) == 32);
	datum_test(datum_blake2b_abw_clear_bits(10) == 42);
	datum_test(datum_blake2b_abw_clear_bits(223) == 255);
	datum_test(datum_blake2b_apply_xor_mask_le(
		masked_hash, raw_hash, xor_key, 42));
	datum_test(!memcmp(masked_hash + 27, raw_hash + 27, 5));
}

static void datum_pow_blake2b_vector_tests(void) {
	/* H1+H2 match Knots CBlockHeader::GetHash with wire version bit 0x80000000 in H1. */
	static const char expected_commitment_hex[] =
		"be3009118e9fbe8be787c9fef5ee1a34c95b92efe7c6f1d430c488e094ce94a8";
	static const char expected_root_hex[] =
		"2ae3e2ac5e7b16faeda5b13386d9b3fb0e5ddfa803deee88eb9a1f6ce65c9110";
	static const char expected_work_hex[] =
		"0000000000008a7f7054908ed879cc78d133dc6604fb0fd017552289799cabd6"
		"01020304050607080403020115161718"
		"2ae3e2ac5e7b16faeda5b13386d9b3fb0e5ddfa803deee88eb9a1f6ce65c9110";
	static const char expected_hash_le_hex[] =
		"15ed05ccf950c40f149ea623b77f7f3f58afb9ab3ab723d5ca5870338c42d935";
	static const char expected_header_hex[] =
		"000000a0c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2f415365ffff7f20"
		"01020304050607081516171800000000a0a1a2a3a4a5a6a7a8a9aaab040302010300040d"
		"101112131415161718191a1b1c1d1e1f39300000"
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
	unsigned char merkle[32], xor_key[16], rhs[32], extranonce[12], prevhash[32];
	unsigned char nonce[8], ntime[8], commitment[32], root[32], work[80], cached_work[80], hash_le[32];
	unsigned char share_target[32];
	unsigned char coinb1[39], arbitrary_tx[51], leaf_preimage[52] = {0};
	unsigned char header[DATUM_BLAKE2B_BLOCK_HEADER_SIZE], expected[DATUM_BLAKE2B_BLOCK_HEADER_SIZE];
	uint32_t time_on_wire;
	
	datum_test(datum_blake2b_time_on_wire(&time_on_wire, 2000000000, 600,
		DATUM_BLAKE2B_USE_TIME_OFFSET));
	datum_test(time_on_wire == 1999999400);
	// Consensus wraps rather than rejecting when the offset exceeds nTime.
	datum_test(datum_blake2b_time_on_wire(&time_on_wire, 599, 600,
		DATUM_BLAKE2B_USE_TIME_OFFSET));
	datum_test(time_on_wire == 4294967295u);
	datum_test(datum_blake2b_time_on_wire(&time_on_wire, 100, 1000,
		DATUM_BLAKE2B_USE_TIME_OFFSET));
	datum_test(time_on_wire == 4294966396u);
	datum_test(!datum_blake2b_time_on_wire(&time_on_wire,
		UINT64_C(0x100000000), 0, 0));
	datum_test(datum_blake2b_time_on_wire(&time_on_wire, 599, 600, 0));
	datum_test(time_on_wire == 599);
	datum_test(datum_blake2b_share_target(share_target, 4));
	for(size_t i=0;i<27;i++) datum_test(share_target[i] == 0xff);
	datum_test(share_target[27] == 0x0f);
	for(size_t i=28;i<32;i++) datum_test(share_target[i] == 0);
	datum_test(!datum_blake2b_share_target(share_target, 224));
	datum_test(datum_blake2b_share_nbits(0) == UINT32_C(0x1d00ffff));
	datum_test(datum_blake2b_share_nbits(1) == UINT32_C(0x1c7fffff));
	datum_test(datum_blake2b_share_nbits(2) == UINT32_C(0x1c3fffff));
	datum_test(datum_blake2b_share_nbits(8) == UINT32_C(0x1c00ffff));
	datum_test(datum_blake2b_share_nbits(224) == 0);
	for(unsigned int pot=0;pot<224;pot++) {
		unsigned char accepted[32], advertised[32];
		datum_test(datum_blake2b_share_target(accepted, pot));
		nbits_to_target(datum_blake2b_share_nbits(pot), advertised);
		datum_test(compare_hashes(advertised, accepted) <= 0);
	}
	datum_test(datum_blake2b_accounting_difficulty(65535.0L) == 65536.0L);
	datum_test(datum_pow_decode_u32_hex_exact("00000000", &time_on_wire));
	datum_test(time_on_wire == 0);
	datum_test(datum_pow_decode_u32_hex_exact("1234aBcD", &time_on_wire));
	datum_test(time_on_wire == UINT32_C(0x1234abcd));
	datum_test(datum_pow_decode_u32_hex_exact("FFFFFFFF", &time_on_wire));
	datum_test(time_on_wire == UINT32_MAX);
	datum_test(!datum_pow_decode_u32_hex_exact("1234567", &time_on_wire));
	datum_test(!datum_pow_decode_u32_hex_exact("1234567g", &time_on_wire));
	datum_test(!datum_pow_decode_u32_hex_exact("123456789", &time_on_wire));
	datum_test(!datum_pow_decode_u32_hex_exact(NULL, &time_on_wire));
	datum_test(!datum_pow_decode_u32_hex_exact("00000000", NULL));
	char difficulty[64];
	datum_test(datum_blake2b_format_stratum_difficulty(
		difficulty, sizeof(difficulty), 1) > 0);
	datum_test(!strcmp(difficulty, "0.9999847412109375"));
	datum_test(datum_blake2b_format_stratum_difficulty(
		difficulty, sizeof(difficulty), 16384) > 0);
	datum_test(!strcmp(difficulty, "16383.75"));
	datum_test(datum_blake2b_format_stratum_difficulty(
		difficulty, sizeof(difficulty), 65536) > 0);
	datum_test(!strcmp(difficulty, "65535"));
	
	for(size_t i=0;i<32;i++) {
		merkle[i] = i;
		rhs[i] = 0x80 + i;
		prevhash[i] = 0xc0 + i;
	}
	for(size_t i=0;i<16;i++) xor_key[i] = 0x10 + i;
	for(size_t i=0;i<12;i++) extranonce[i] = 0xa0 + i;
	for(size_t i=0;i<8;i++) nonce[i] = 1 + i;
	pk_u32le(ntime, 0, UINT32_C(0x01020304));
	pk_u32le(ntime, 4, UINT32_C(0x18171615));
	datum_test(datum_blake2b_header_commitment(commitment, 0x20000000, prevhash,
		12345, merkle, 0x6553412f, 0x207fffff, 3, DATUM_BLAKE2B_USE_TIME_OFFSET, 13,
		xor_key, rhs));
	datum_test(datum_pow_decode_hex_exact(expected_commitment_hex, 32, expected));
	datum_test(!memcmp(commitment, expected, 32));
	datum_test(datum_blake2b_work_root(root, commitment, extranonce));
	datum_test(datum_pow_decode_hex_exact(expected_root_hex, 32, expected));
	datum_test(!memcmp(root, expected, 32));
	datum_blake2b_coinb1(coinb1, commitment);
	memcpy(arbitrary_tx, coinb1, sizeof(coinb1));
	memcpy(arbitrary_tx + sizeof(coinb1), extranonce, sizeof(extranonce));
	memcpy(leaf_preimage + 1, arbitrary_tx, sizeof(arbitrary_tx));
	datum_test(datum_blake2b_256(expected, leaf_preimage, sizeof(leaf_preimage)));
	datum_test(!memcmp(root, expected, 32));
	datum_blake2b_build_work_header(work, prevhash, nonce, ntime, root);
	datum_test(datum_pow_decode_hex_exact(expected_work_hex, sizeof(work), expected));
	datum_test(!memcmp(work, expected, sizeof(work)));
	datum_blake2b_prevblock_hidden(expected, prevhash);
	datum_test(!memcmp(expected, work, 32));
	datum_blake2b_build_work_header_from_hidden(cached_work, expected, nonce, ntime, root);
	datum_test(!memcmp(cached_work, work, sizeof(work)));
	datum_test(datum_blake2b_pow_hash_le(hash_le, work, xor_key, 13));
	datum_test(datum_pow_decode_hex_exact(expected_hash_le_hex, 32, expected));
	datum_test(!memcmp(hash_le, expected, 32));
	datum_blake2b_serialize_block_header(header, 0x20000000, prevhash, merkle,
		0x6553412f, 0x207fffff, nonce, ntime, extranonce, 3,
		DATUM_BLAKE2B_USE_TIME_OFFSET, 13, xor_key, 12345, rhs);
	datum_test(datum_pow_decode_hex_exact(expected_header_hex, sizeof(header), expected));
	datum_test(!memcmp(header, expected, sizeof(header)));
	datum_test(!datum_pow_decode_hex_exact("xyz", 1, nonce));
	
	/* Canonical profile-0 vector published with Knots' header-v2 implementation:
	 * profile_0_time_offset from src/test/data/block_header_v2.json. Its "h2",
	 * "blake2b_1", "asic_input", and the byte-reverse of its "block_hash".
	 * Taken from the published file rather than recomputed, so the test pins the
	 * gateway to consensus rather than to itself. m_flags is 28 (0x1c) there;
	 * 0x5c would additionally set 0x40, which Knots rejects as bad-flags-highbits
	 * (validation.cpp: `block.m_flags & 0xc0`). */
	{
		static const char knots_prevhash_hex[] =
			"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
		static const char knots_merkle_hex[] =
			"00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0";
		static const char knots_rhs_hex[] =
			"8967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";
		static const char knots_commitment_hex[] =
			"ab5becb2336a3701557b0f6e33de39bd333072b8494c7c60952a8e8a636565e3";
		static const char knots_root_hex[] =
			"7e6326906eaa52fe59e03a14f1dfb8dd5d6e78497e56a8a6e4f4fb4d385e43db";
		static const char knots_work_hex[] =
			"000000000000943aff74219e1f45899abfdf536373c0f2fc92e6fe58335cd0ad"
			"0df0ad0b4433221158020000efcdab89"
			"7e6326906eaa52fe59e03a14f1dfb8dd5d6e78497e56a8a6e4f4fb4d385e43db";
		static const char knots_hash_le_hex[] =
			"04d78755b174467ec8537c230912ddd9bc4f28229b795b78490ad705cf5d494b";
		unsigned char knots_prevhash[32], knots_merkle[32], knots_rhs[32];
		unsigned char knots_nonce[8], knots_ntime[8];
		
		datum_test(datum_pow_decode_hex_exact(knots_prevhash_hex, 32, knots_prevhash));
		datum_test(datum_pow_decode_hex_exact(knots_merkle_hex, 32, knots_merkle));
		datum_test(datum_pow_decode_hex_exact(knots_rhs_hex, 32, knots_rhs));
		memset(xor_key, 0, sizeof(xor_key));
		pk_u32le(knots_nonce, 0, UINT32_C(0x0badf00d));
		pk_u32le(knots_nonce, 4, UINT32_C(0x11223344));
		pk_u32le(knots_ntime, 0, UINT32_C(600));
		pk_u32le(knots_ntime, 4, UINT32_C(0x89abcdef));
		
		datum_test(datum_blake2b_header_commitment(commitment, 0x20000000,
			knots_prevhash, 840000, knots_merkle, UINT32_C(2000000000) - 600,
			0x1d00ffff, 3, 0x1c, 0, xor_key, knots_rhs));
		datum_test(datum_pow_decode_hex_exact(knots_commitment_hex, 32, expected));
		datum_test(!memcmp(commitment, expected, 32));
		
		datum_test(datum_pow_decode_hex_exact(knots_root_hex, 32, root));
		datum_blake2b_build_work_header(work, knots_prevhash, knots_nonce,
			knots_ntime, root);
		datum_test(datum_pow_decode_hex_exact(knots_work_hex, sizeof(work), expected));
		datum_test(!memcmp(work, expected, sizeof(work)));
		datum_test(datum_blake2b_pow_hash_le(hash_le, work, xor_key, 0));
		datum_test(datum_pow_decode_hex_exact(knots_hash_le_hex, 32, expected));
		datum_test(!memcmp(hash_le, expected, 32));
	}
}

void datum_pow_tests(void) {
	datum_blake2b_share_ntime_tests();
	datum_blake2b_abw_pow_tests();
	datum_pow_blake2b_vector_tests();
}
