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

/* P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG, 25 bytes. */
static const unsigned char datum_test_p2pkh_script[25] = {0x76, 0xa9, 0x14, [23] = 0x88, 0xac};
/* P2WPKH: OP_0 <20 bytes>, 22 bytes. */
static const unsigned char datum_test_p2wpkh_script[22] = {0x00, 0x14};

/* Builds one coinbase class with the template's used sigop cost set to
 * sigops_used and the pool script set to P2PKH or P2WPKH, and returns the hex
 * output count that follows the 8-character sequence at the start of coinb2.
 * The count covers the included outputs plus the pool output and the witness
 * commitment. The job's candidate outputs are two P2PKH outputs (cost 4 each)
 * and one P2WPKH output (cost 0). */
static const char *datum_coinbase_output_count_hex(T_DATUM_STRATUM_JOB *job, uint32_t sigops_used, bool pool_p2pkh) {
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
	memset(job->coinbase[1].coinb2, 0, sizeof(job->coinbase[1].coinb2));
	generate_coinbase_txns_for_stratum_job_subtypebysize(job, 1, 1000, true, cb1idx, cb2idx);
	return job->coinbase[1].coinb2 + 8;
}

static void datum_blake2b_coinbase_sigops_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	int k;
	
	datum_test(job != NULL);
	if (!job) return;
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
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 0, false), "05", 2));
	/* Budget for one P2PKH output: the first P2PKH is included, the second is
	 * skipped, and the P2WPKH is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 80000 - 4, false), "04", 2));
	/* Budget of 0: only the P2WPKH output is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 80000, false), "03", 2));
	/* A P2PKH pool output takes the remaining 4 units of the budget, so neither
	 * P2PKH candidate is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 80000 - 4, true), "03", 2));
	free(job);
}

/* A split of MAX_COINBASER_OUTPUTS P2WPKH outputs, 31 bytes each, fits one
 * coinbase: the output count is written as a three-byte varint and the hex of
 * coinb2 stays inside STRATUM_COINBASE2_MAX_LEN. */
static void datum_blake2b_large_coinbase_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	int cb1idx[MAX_COINBASE_TYPES] = {0};
	int cb2idx[MAX_COINBASE_TYPES] = {0};
	size_t cb_bytes;
	int k;
	
	datum_test(job != NULL);
	if (!job) return;
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
		job, COINBASE_TYPE_YUGE, MAX_COINBASER_OUTPUTS * 31, true, cb1idx, cb2idx);
	
	/* MAX_COINBASER_OUTPUTS dictated outputs, the pool output and the witness
	 * commitment: 1026, written as fd followed by 0x0402 little-endian. */
	datum_test(!strncmp(job->coinbase[COINBASE_TYPE_YUGE].coinb2 + 8, "fd0204", 6));
	datum_test(strlen(job->coinbase[COINBASE_TYPE_YUGE].coinb2) < STRATUM_COINBASE2_MAX_LEN);
	cb_bytes = (strlen(job->coinbase[COINBASE_TYPE_YUGE].coinb1) +
		strlen(job->coinbase[COINBASE_TYPE_YUGE].coinb2)) / 2 + 12;
	datum_test(cb_bytes > 30000 && cb_bytes <= MAX_DICTATED_COINBASE_SIZE);
	free(job);
}

void datum_coinbaser_tests(void) {
	datum_prime_id_64bit_tests();
	datum_blake2b_coinbase_limit_tests();
	datum_blake2b_coinbase_sigops_tests();
	datum_blake2b_large_coinbase_tests();
}
