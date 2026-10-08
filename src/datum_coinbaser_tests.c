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
#include <stdlib.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_coinbaser.h"
#include "datum_utils.h"
#include "datum_pow.h"

int datum_stratum_coinbase_fit_to_template(
	int max_sz, int fixed_bytes, T_DATUM_STRATUM_JOB *s);

static void datum_prime_id_64bit_tests(void) {
	const uint64_t saved_prime_id = datum_config.prime_id;
	const uint16_t saved_unique_id = datum_config.coinbase_unique_id;
	char coinbase_input[1024] = {0};
	int target_pot_index = -1;
	
	datum_config.prime_id = UINT64_C(0x887766555d965e4e);
	datum_config.coinbase_unique_id = 0x1234;
	const int coinbase_input_size = generate_coinbase_input(
		42, coinbase_input, &target_pot_index);
	datum_test(coinbase_input_size >= target_pot_index + 11);
	datum_test(!strncmp(
		coinbase_input + target_pot_index * 2,
		"ff34124e5e965d55667788", 22));
	datum_config.prime_id = saved_prime_id;
	datum_config.coinbase_unique_id = saved_unique_id;
}

static void datum_blake2b_coinbase_limit_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	job.block_template = &tdata;
	tdata.sizelimit = 85 + 36 + 950;
	tdata.weightlimit = 4000000;
	
	/* The 164-byte header shrinks the coinbase leftover by 84 bytes. */
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 866);
	
	/* The weight limit: the header and a five-byte count at four units a byte,
	 * the coinbase's 36 witness bytes, then 950 bytes of coinbase at four
	 * each. With the 80-byte header's 340 the leftover was 1000 (unbound). */
	tdata.sizelimit = 4000000;
	tdata.weightlimit = ((DATUM_BLAKE2B_BLOCK_HEADER_SIZE + 5) * 4) + 36 + (4 * 950);
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 950);
	/* The transactions' weight counts the same way. */
	tdata.txn_total_weight = 4000;
	tdata.weightlimit += 4000;
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 950);
	/* Fixed bytes are subtracted from the leftover. */
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 100, &job) == 850);
}

static void datum_coinbaser_value_overflow_tests(void) {
	T_DATUM_STRATUM_JOB job = {.coinbase_value = UINT64_C(5000000000)};
	unsigned char response[] = {
		1,
		1, 0, 0, 0, 0, 0, 0, 0, 2, 0x51, 0x51,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0x51, 0x51,
	};
	
	datum_test(datum_coinbaser_v2_parse(&job, response, sizeof(response)) == 1);
	datum_test(job.available_coinbase_outputs_count == 1);
	datum_test(job.available_coinbase_outputs[0].value_sats == 1);
}

/* P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG, 25 bytes. */
static const unsigned char datum_test_p2pkh_script[25] = {0x76, 0xa9, 0x14, [23] = 0x88, 0xac};
/* P2WPKH: OP_0 <20 bytes>, 22 bytes. */
static const unsigned char datum_test_p2wpkh_script[22] = {0x00, 0x14};
/* Bare P2PK: <33-byte key> OP_CHECKSIG, 35 bytes. */
static const unsigned char datum_test_p2pk_script[35] = {0x21, [34] = 0xac};
/* Bare 1-of-1 multisig: OP_1 <33-byte key> OP_1 OP_CHECKMULTISIG, 37 bytes. */
static const unsigned char datum_test_multisig_script[37] = {0x51, 0x21, [35] = 0x51, 0xae};

/* datum_script_sigop_cost against Bitcoin's legacy count times 4. */
static void datum_script_sigop_cost_tests(void) {
	static const unsigned char p2sh[23] = {0xa9, 0x14, [22] = 0x87};
	static const unsigned char p2tr[34] = {0x51, 0x20};
	static const unsigned char checksigverify[1] = {0xad};
	static const unsigned char checkmultisigverify[1] = {0xaf};
	static const unsigned char several[3] = {0xac, 0xac, 0xae};
	/* Opcode bytes inside pushed data are not counted. */
	static const unsigned char pushed[4] = {0x03, 0xac, 0xac, 0xac};
	static const unsigned char pushdata1[4] = {0x4c, 0x02, 0xae, 0xae};
	static const unsigned char pushdata2[6] = {0x4d, 0x02, 0x00, 0xac, 0xac, 0xac};
	/* Counting stops at a push that runs past the end, or whose length does. */
	static const unsigned char truncated_push[3] = {0xac, 0x05, 0xac};
	static const unsigned char truncated_length[3] = {0xac, 0x4d, 0x01};
	
	datum_test(datum_script_sigop_cost(datum_test_p2pkh_script, sizeof(datum_test_p2pkh_script)) == 4);
	datum_test(datum_script_sigop_cost(datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script)) == 0);
	datum_test(datum_script_sigop_cost(p2sh, sizeof(p2sh)) == 0);
	datum_test(datum_script_sigop_cost(p2tr, sizeof(p2tr)) == 0);
	datum_test(datum_script_sigop_cost(datum_test_p2pk_script, sizeof(datum_test_p2pk_script)) == 4);
	datum_test(datum_script_sigop_cost(datum_test_multisig_script, sizeof(datum_test_multisig_script)) == 80);
	datum_test(datum_script_sigop_cost(checksigverify, sizeof(checksigverify)) == 4);
	datum_test(datum_script_sigop_cost(checkmultisigverify, sizeof(checkmultisigverify)) == 80);
	datum_test(datum_script_sigop_cost(several, sizeof(several)) == 88);
	datum_test(datum_script_sigop_cost(pushed, sizeof(pushed)) == 0);
	datum_test(datum_script_sigop_cost(pushdata1, sizeof(pushdata1)) == 0);
	datum_test(datum_script_sigop_cost(pushdata2, sizeof(pushdata2)) == 4);
	datum_test(datum_script_sigop_cost(truncated_push, sizeof(truncated_push)) == 4);
	datum_test(datum_script_sigop_cost(truncated_length, sizeof(truncated_length)) == 4);
}

/* The coinbaser parser charges each dictated output its script's cost. */
static void datum_coinbaser_parse_sigops_tests(void) {
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	unsigned char response[1 + 2 * 9 + sizeof(datum_test_p2pk_script) + sizeof(datum_test_multisig_script)];
	size_t i = 0;
	
	datum_test(job != NULL);
	if (!job) return;
	job->coinbase_value = 5000000000ULL;
	response[i++] = 1;
	pk_u64le(response, i, 1000); i += 8;
	response[i++] = sizeof(datum_test_p2pk_script);
	memcpy(&response[i], datum_test_p2pk_script, sizeof(datum_test_p2pk_script)); i += sizeof(datum_test_p2pk_script);
	pk_u64le(response, i, 1000); i += 8;
	response[i++] = sizeof(datum_test_multisig_script);
	memcpy(&response[i], datum_test_multisig_script, sizeof(datum_test_multisig_script)); i += sizeof(datum_test_multisig_script);
	
	datum_test(datum_coinbaser_v2_parse(job, response, (int)i) == 2);
	datum_test(job->available_coinbase_outputs[0].sigops == 4);
	datum_test(job->available_coinbase_outputs[1].sigops == 80);
	free(job);
}

/* Builds one coinbase class in hex with the template's used sigop cost set to
 * sigops_used and the pool script set to P2PKH or P2WPKH, and returns the hex
 * output count that follows the 8-character sequence at the start of coinb2.
 * The count covers the included outputs plus the pool output and the witness
 * commitment. The job's candidate outputs are two P2PKH outputs (cost 4 each)
 * and one P2WPKH output (cost 0). */
static const char *datum_coinbase_output_count_hex(T_DATUM_STRATUM_JOB *job, T_DATUM_COINBASE_HEX *hex, uint32_t sigops_used, bool pool_p2pkh) {
	int cb1idx[MAX_COINBASE_TYPES] = {0};
	int cb2idx[MAX_COINBASE_TYPES] = {0};
	
	job->block_template->txn_total_sigops = sigops_used;
	if (pool_p2pkh) {
		memcpy(job->pool_addr_script, datum_test_p2pkh_script, sizeof(datum_test_p2pkh_script));
		job->pool_addr_script_len = sizeof(datum_test_p2pkh_script);
	} else {
		memcpy(job->pool_addr_script, datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script));
		job->pool_addr_script_len = sizeof(datum_test_p2wpkh_script);
	}
	memset(hex[1].coinb2, 0, sizeof(hex[1].coinb2));
	generate_coinbase_txns_for_stratum_job_subtypebysize(job, hex, 1, 1000, true, cb1idx, cb2idx, false);
	return hex[1].coinb2 + 8;
}

static void datum_blake2b_coinbase_sigops_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	int cb1idx[MAX_COINBASE_TYPES] = {0};
	int cb2idx[MAX_COINBASE_TYPES] = {0};
	T_DATUM_COINBASE_HEX *hex = calloc(MAX_COINBASE_TYPES, sizeof(*hex));
	int k;
	
	datum_test(job != NULL && hex != NULL);
	if (!job || !hex) {
		free(job);
		free(hex);
		return;
	}
	memset(&tdata, 0, sizeof(tdata));
	tdata.sigoplimit = 80000;
	job->block_template = &tdata;
	job->coinbase_value = 5000000000ULL;
	for (k = 0; k < 3; k++) {
		job->available_coinbase_outputs[k].value_sats = 100000000;
		if (k < 2) {
			memcpy(job->available_coinbase_outputs[k].output_script, datum_test_p2pkh_script, sizeof(datum_test_p2pkh_script));
			job->available_coinbase_outputs[k].output_script_len = sizeof(datum_test_p2pkh_script);
			job->available_coinbase_outputs[k].sigops = 4;
		} else {
			memcpy(job->available_coinbase_outputs[k].output_script, datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script));
			job->available_coinbase_outputs[k].output_script_len = sizeof(datum_test_p2wpkh_script);
			job->available_coinbase_outputs[k].sigops = 0;
		}
	}
	job->available_coinbase_outputs_count = 3;
	
	/* Space for every output: all three, the pool output and the witness commitment. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, hex, 0, false), "05", 2));
	/* Budget for one P2PKH output: the first P2PKH is included, the second is
	 * skipped, and the P2WPKH is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, hex, 80000 - 4, false), "04", 2));
	/* Budget of 0: only the P2WPKH output is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, hex, 80000, false), "03", 2));
	/* A P2PKH pool output takes the remaining 4 units of the budget, so neither
	 * P2PKH candidate is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, hex, 80000 - 4, true), "03", 2));
	/* A bare P2PK pool output is charged its script's cost, 4, the same as a
	 * P2PKH one. */
	memcpy(job->pool_addr_script, datum_test_p2pk_script, sizeof(datum_test_p2pk_script));
	job->pool_addr_script_len = sizeof(datum_test_p2pk_script);
	tdata.txn_total_sigops = 80000 - 4;
	memset(hex[1].coinb2, 0, sizeof(hex[1].coinb2));
	generate_coinbase_txns_for_stratum_job_subtypebysize(job, hex, 1, 1000, true, cb1idx, cb2idx, false);
	datum_test(!strncmp(hex[1].coinb2 + 8, "03", 2));
	free(hex);
	free(job);
}

/* A split of MAX_COINBASER_OUTPUTS P2WPKH outputs, 31 bytes each, fits one
 * coinbase: the output count is written as a three-byte varint and the hex of
 * coinb2 stays inside STRATUM_COINBASE2_MAX_LEN. */
static void datum_blake2b_large_coinbase_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	T_DATUM_COINBASE_HEX *hex = calloc(MAX_COINBASE_TYPES, sizeof(*hex));
	int cb1idx[MAX_COINBASE_TYPES] = {0};
	int cb2idx[MAX_COINBASE_TYPES] = {0};
	size_t cb_bytes;
	int k;

	datum_test(job != NULL && hex != NULL);
	if (!job || !hex) {
		free(job);
		free(hex);
		return;
	}
	memset(&tdata, 0, sizeof(tdata));
	tdata.sigoplimit = 80000;
	job->block_template = &tdata;
	job->coinbase_value = 5000000000ULL;
	memcpy(job->pool_addr_script, datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script));
	job->pool_addr_script_len = sizeof(datum_test_p2wpkh_script);
	for (k = 0; k < MAX_COINBASER_OUTPUTS; k++) {
		job->available_coinbase_outputs[k].value_sats = 1000;
		memcpy(job->available_coinbase_outputs[k].output_script, datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script));
		job->available_coinbase_outputs[k].output_script_len = sizeof(datum_test_p2wpkh_script);
		job->available_coinbase_outputs[k].sigops = 0;
	}
	job->available_coinbase_outputs_count = MAX_COINBASER_OUTPUTS;

	generate_coinbase_txns_for_stratum_job_subtypebysize(
		job, hex, COINBASE_TYPE_YUGE, MAX_COINBASER_OUTPUTS * 31, true, cb1idx, cb2idx, false);

	/* MAX_COINBASER_OUTPUTS dictated outputs, the pool output and the witness
	 * commitment: 1026, written as fd followed by 0x0402 little-endian. */
	datum_test(!strncmp(hex[COINBASE_TYPE_YUGE].coinb2 + 8, "fd0204", 6));
	datum_test(strlen(hex[COINBASE_TYPE_YUGE].coinb2) < STRATUM_COINBASE2_MAX_LEN);
	cb_bytes = (strlen(hex[COINBASE_TYPE_YUGE].coinb1) +
		strlen(hex[COINBASE_TYPE_YUGE].coinb2)) / 2 + 12;
	datum_test(cb_bytes > 30000 && cb_bytes <= MAX_DICTATED_COINBASE_SIZE);
	free(hex);
	free(job);
}

/* The job keeps the binary of the hex the builder writes. With no pool
 * connected the job is built empty: class 0 is version 1 and one input in
 * coinb1, then in coinb2 the sequence, two outputs (the pool's at the coinbase
 * value and the witness commitment) and the lock time. Every other class is a
 * copy of class 0, and the subsidy-only coinbase pays the block reward in its
 * one output. */
static void datum_coinbase_binary_parts_tests(void) {
	static const unsigned char version_and_input_count[5] = {1, 0, 0, 0, 1};
	static const unsigned char sequence_and_two_outputs[5] = {0xff, 0xff, 0xff, 0xff, 2};
	static const unsigned char sequence_and_one_output[5] = {0xff, 0xff, 0xff, 0xff, 1};
	static const unsigned char lock_time[4] = {0};
	const global_config_t saved_config = datum_config;
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	const T_DATUM_STRATUM_COINBASE *cb;
	unsigned char value[8];
	int k;
	
	datum_test(job != NULL);
	if (!job) return;
	snprintf(datum_config.mining_pool_address, sizeof(datum_config.mining_pool_address),
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
	datum_config.mining_coinbase_tag_primary[0] = 0;
	datum_config.mining_coinbase_tag_secondary[0] = 0;
	memset(&tdata, 0, sizeof(tdata));
	snprintf(tdata.default_witness_commitment, sizeof(tdata.default_witness_commitment),
		"6a24aa21a9ed%064d", 0);
	job->block_template = &tdata;
	job->height = 1000;
	job->coinbase_value = 5000001234ULL;
	
	generate_coinbase_txns_for_stratum_job(job, true);
	
	cb = &job->coinbase[0];
	datum_test(cb->coinb1_len > (int)sizeof(version_and_input_count));
	datum_test(!memcmp(cb->coinb1_bin, version_and_input_count, sizeof(version_and_input_count)));
	/* sequence, count, pool output (8 + 1 + 22), witness commitment (8 + 1 + 38), lock time */
	datum_test(cb->coinb2_len == 4 + 1 + 31 + 47 + 4);
	datum_test(!memcmp(cb->coinb2_bin, sequence_and_two_outputs, sizeof(sequence_and_two_outputs)));
	pk_u64le(value, 0, job->coinbase_value);
	datum_test(!memcmp(cb->coinb2_bin + 5, value, sizeof(value)));
	datum_test(!memcmp(cb->coinb2_bin + cb->coinb2_len - 4, lock_time, sizeof(lock_time)));
	for (k = 1; k < MAX_COINBASE_TYPES; k++) {
		datum_test(job->coinbase[k].coinb1_len == cb->coinb1_len);
		datum_test(job->coinbase[k].coinb2_len == cb->coinb2_len);
		datum_test(!memcmp(job->coinbase[k].coinb1_bin, cb->coinb1_bin, cb->coinb1_len));
		datum_test(!memcmp(job->coinbase[k].coinb2_bin, cb->coinb2_bin, cb->coinb2_len));
	}
	
	cb = &job->subsidy_only_coinbase;
	datum_test(cb->coinb1_len == job->coinbase[0].coinb1_len);
	datum_test(!memcmp(cb->coinb1_bin, job->coinbase[0].coinb1_bin, cb->coinb1_len));
	datum_test(cb->coinb2_len == 4 + 1 + 31 + 4);
	datum_test(!memcmp(cb->coinb2_bin, sequence_and_one_output, sizeof(sequence_and_one_output)));
	pk_u64le(value, 0, block_reward(job->height));
	datum_test(!memcmp(cb->coinb2_bin + 5, value, sizeof(value)));
	datum_test(!memcmp(cb->coinb2_bin + 13, job->coinbase[0].coinb2_bin + 13, 23));
	datum_test(!memcmp(cb->coinb2_bin + cb->coinb2_len - 4, lock_time, sizeof(lock_time)));
	
	datum_config = saved_config;
	free(job);
}

void datum_coinbaser_tests(void) {
	datum_prime_id_64bit_tests();
	datum_blake2b_coinbase_limit_tests();
	datum_coinbaser_value_overflow_tests();
	datum_blake2b_coinbase_sigops_tests();
	datum_script_sigop_cost_tests();
	datum_coinbaser_parse_sigops_tests();
	datum_blake2b_large_coinbase_tests();
	datum_coinbase_binary_parts_tests();
}
