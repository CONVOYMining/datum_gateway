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
 * Copyright (c) 2025-2026 Bitcoin Ocean, LLC, Luke Dashjr, and individual contributors
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "datum_jsonrpc.h"
#include "datum_pow.h"
#include "datum_stratum.h"
#include "datum_utils.h"

void stratum_calculate_merkle_branches(T_DATUM_STRATUM_JOB *s);
int client_mining_submit(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);

static void datum_blake2b_refresh_time_offset_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	unsigned char expected_hidden[32];
	char expected_hex[65];
	
	/* A job snapshots whether miners may submit a time offset. */
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	job.block_template = &tdata;
	tdata.curtime = 2000000000;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	datum_test(job.blake2b_flags == DATUM_BLAKE2B_USE_TIME_OFFSET);
	datum_blake2b_prevblock_hidden(expected_hidden, tdata.previousblockhash_bin);
	datum_test(!memcmp(job.blake2b_prevblock_hidden, expected_hidden, sizeof(expected_hidden)));
	for (size_t i = 0; i < sizeof(expected_hidden); i++) {
		uchar_to_hex(expected_hex + (i << 1), expected_hidden[i]);
	}
	expected_hex[64] = 0;
	datum_test(!strcmp(job.prevhash, expected_hex));
	
	/* Without the flag the offset is ignored and curtime goes on the wire as is. */
	tdata.curtime = 2000000000;
	job.blake2b_flags = 0;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	
	/* An unrepresentable base time clears the interpretation flag. */
	tdata.curtime = (uint64_t)UINT32_MAX + 1;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == (uint32_t)tdata.curtime);
	datum_test(job.blake2b_flags == 0);
}

static void datum_blake2b_client_pot_commitment_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	unsigned char c_ff[32], c_pot[32], c_variant[32], c_subsidy[32], c_local[32];
	unsigned char c_from_txn[32];
	unsigned char ff[39], pot[39];
	unsigned char cb_txn[64];
	size_t cb_len;
	
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	tdata.version = 0x20000000;
	tdata.height = 12345;
	tdata.bits_uint = 0x1d00ffff;
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(
		tdata.xor_key_hash, (const unsigned char[16]){0}));
	job.block_template = &tdata;
	job.is_datum_job = true;
	job.blake2b_time_on_wire = 1000;
	job.coinbase[0].coinb1_len = 20;
	job.coinbase[0].coinb2_len = 8;
	memset(job.coinbase[0].coinb1_bin, 0x11, 20);
	memset(job.coinbase[0].coinb2_bin, 0x22, 8);
	job.coinbase[0].coinb1_bin[4] = 0xFF;
	job.coinbase[2] = job.coinbase[0];
	job.coinbase[2].coinb2_bin[0] ^= 0x55;
	job.subsidy_only_coinbase = job.coinbase[0];
	job.subsidy_only_coinbase.coinb2_bin[0] ^= 0xaa;
	job.target_pot_index = 4;
	tdata.txn_count = 1;
	
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 0xFF, c_ff, ff));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 14, c_pot, pot));
	datum_test(memcmp(c_ff, c_pot, 32) != 0);
	datum_test(memcmp(ff, pot, 39) != 0);
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[2], false, 14, c_variant, NULL));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.subsidy_only_coinbase, true, 14, c_subsidy, NULL));
	datum_test(memcmp(c_variant, c_pot, 32) != 0);
	datum_test(memcmp(c_subsidy, c_pot, 32) != 0);
	
	cb_len = (size_t)job.coinbase[0].coinb1_len + 12 + (size_t)job.coinbase[0].coinb2_len;
	memcpy(cb_txn, job.coinbase[0].coinb1_bin, job.coinbase[0].coinb1_len);
	memset(cb_txn + job.coinbase[0].coinb1_len, 0, 12);
	memcpy(cb_txn + job.coinbase[0].coinb1_len + 12, job.coinbase[0].coinb2_bin, job.coinbase[0].coinb2_len);
	cb_txn[job.target_pot_index] = 14;
	datum_test(datum_stratum_job_blake2b_commitment_from_txn(
		&job, cb_txn, cb_len, 14, false, c_from_txn));
	datum_test(!memcmp(c_from_txn, c_pot, 32));
	
	cb_len = (size_t)job.subsidy_only_coinbase.coinb1_len + 12 +
		(size_t)job.subsidy_only_coinbase.coinb2_len;
	memcpy(cb_txn, job.subsidy_only_coinbase.coinb1_bin,
		job.subsidy_only_coinbase.coinb1_len);
	memset(cb_txn + job.subsidy_only_coinbase.coinb1_len, 0, 12);
	memcpy(cb_txn + job.subsidy_only_coinbase.coinb1_len + 12,
		job.subsidy_only_coinbase.coinb2_bin,
		job.subsidy_only_coinbase.coinb2_len);
	cb_txn[job.target_pot_index] = 14;
	datum_test(datum_stratum_job_blake2b_commitment_from_txn(
		&job, cb_txn, cb_len, 14, true, c_from_txn));
	datum_test(!memcmp(c_from_txn, c_subsidy, 32));
	
	// Work without an assignment commits to the null XOR key.
	tdata.abw_enabled = false;
	tdata.abw_assignment_id = 0;
	job.is_datum_job = false;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
	datum_test(memcmp(c_local, c_pot, sizeof(c_local)) != 0);
	
	// Pooled work can also operate without ABW.
	job.is_datum_job = true;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
}

static void datum_blake2b_unmasked_block_tests(void) {
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA block_template = {0};
	unsigned char hash[32] = {0};
	
	job.block_template = &block_template;
	memset(job.block_target, 0xff, sizeof(job.block_target));
	datum_test(datum_stratum_share_is_unmasked_block(&job, hash));
	job.is_datum_job = true;
	datum_test(datum_stratum_share_is_unmasked_block(&job, hash));
	block_template.abw_enabled = true;
	datum_test(!datum_stratum_share_is_unmasked_block(&job, hash));
}

static void datum_blake2b_h_not_zero_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB *saved_job = global_cur_stratum_jobs[0];
	char submit[] =
		"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
		"\"miner\",\"0000000000c0de00\",\"0000000000000000\","
		"\"00000000\",\"00000000\"]}";
	static const char expected[] =
		"{\"error\":[23,\"H-not-zero\",null],\"id\":7,\"result\":null}\n";
	
	client.app_client_data = &miner;
	job.block_template = &tdata;
	job.target_pot_index = 0;
	job.coinbase[0].coinb1_len = 1;
	job.coinbase[0].coinb1_bin[0] = 0xff;
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(tdata.xor_key_hash,
		(const unsigned char[16]){0}));
	strcpy(job.job_id, "0000000000c0de00");
	miner.stratum_job_diffs[0] = 1;
	global_cur_stratum_jobs[0] = &job;
	
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
	datum_test(miner.share_count_rejected == 1);
	datum_test(client.out_buf == (int)strlen(expected));
	datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
	
	global_cur_stratum_jobs[0] = saved_job;
}

static void datum_blake2b_malformed_submit_hex_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB *saved_job = global_cur_stratum_jobs[0];
	static const char * const submits[] = {
		"{\"id\":8,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0dg00\",\"0000000000000000\",\"00000000\",\"00000000\"]}",
		"{\"id\":8,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de00\",\"000000000000000g\",\"00000000\",\"00000000\"]}",
		"{\"id\":8,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de00\",\"0000000000000000\",\"0000000g\",\"00000000\"]}",
		"{\"id\":8,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de00\",\"0000000000000000\",\"000000000000000g\",\"00000000\"]}",
		"{\"id\":8,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de00\",\"0000000000000000\",\"00000000\",\"0000000g\"]}",
		"{\"id\":8,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de00\",\"0000000000000000\",\"00000000\",\"000000000000000g\"]}",
	};
	static const char expected[] =
		"{\"error\":[20,\"unknown-work\",null],\"id\":8,\"result\":null}\n";
	char submit[192];

	client.app_client_data = &miner;
	job.block_template = &tdata;
	job.target_pot_index = 0;
	job.coinbase[0].coinb1_len = 1;
	job.coinbase[0].coinb1_bin[0] = 0xff;
	strcpy(job.job_id, "0000000000c0de00");
	miner.stratum_job_diffs[0] = 1;
	global_cur_stratum_jobs[0] = &job;

	for (size_t i = 0; i < sizeof(submits) / sizeof(submits[0]); i++) {
		const uint64_t rejected_before = miner.share_count_rejected;
		client.out_buf = 0;
		strcpy(submit, submits[i]);
		datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
		datum_test(miner.share_count_rejected == rejected_before + 1);
		datum_test(client.out_buf == (int)strlen(expected));
		datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
	}

	global_cur_stratum_jobs[0] = saved_job;
}

static void datum_blake2b_coinbase_selection_tests(void) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_MINER_DATA miner = {.coinbase_selection = 3};
	
	datum_test(sdata != NULL);
	if (!sdata) return;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, true) == DATUM_COINBASE_ID_EMPTY);
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	sdata->cur_stratum_job = &job;
	sdata->full_coinbase_ready = true;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	job.job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 3);
	miner.coinbase_selection = MAX_COINBASE_TYPES;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	free(sdata);
}

static void datum_stratum_abw_block_request_tests(void) {
	unsigned char xor_key[16];
	unsigned char raw_hash[32], masked_hash[32];
	for (size_t i = 0; i < sizeof(xor_key); ++i) {
		xor_key[i] = (unsigned char)(i + 1);
	}
	for (size_t i = 0; i < sizeof(raw_hash); ++i) {
		raw_hash[i] = (unsigned char)(0x80 + i);
	}
	datum_test(datum_blake2b_apply_xor_mask_le(
		masked_hash, raw_hash, xor_key, 42));
	
	unsigned char header[DATUM_BLAKE2B_BLOCK_HEADER_SIZE] = {0};
	const unsigned char coinbase[] = {1, 0, 0, 0, 0, 0, 0, 0};
	const char transactions_hex[] = "0102";
	char request[2048], original[2048], block_hash[65];
	size_t header_offset = 0;
	header[DATUM_BLAKE2B_HEADER_XOR_CLEAR_BITS_OFFSET] = 42;
	const size_t request_size = datum_stratum_build_block_request_parts(
		request, sizeof(request), header, coinbase, sizeof(coinbase), false,
		1, transactions_hex, sizeof(transactions_hex) - 1, false,
		&header_offset);
	datum_test(request_size > 0);
	datum_test(strstr(request, "0102\"]}") != NULL);
	memcpy(original, request, request_size + 1);
	unsigned char wrong_hash[32];
	memcpy(wrong_hash, masked_hash, sizeof(wrong_hash));
	wrong_hash[0] ^= 1;
	datum_test(!datum_stratum_abw_finalize_block_request(request,
		request_size, header_offset, raw_hash, 42, xor_key,
		wrong_hash, block_hash));
	datum_test(!memcmp(request, original, request_size + 1));
	datum_test(datum_stratum_abw_finalize_block_request(request,
		request_size, header_offset, raw_hash, 42, xor_key,
		masked_hash, block_hash));
	datum_test(!memcmp(request + header_offset +
		DATUM_BLAKE2B_HEADER_XOR_KEY_OFFSET * 2, "01020304", 8));
	for (size_t i = 0; i < sizeof(masked_hash); ++i) {
		datum_test(hex2bin_uchar(block_hash + i * 2) == masked_hash[31 - i]);
	}
}

static void datum_block_coinbase_witness_tests(void) {
	static const unsigned char stripped[] = {
		0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	};
	static const unsigned char witnessed[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	};
	static const char zero_witness[] =
		"01200000000000000000000000000000000000000000000000000000000000000000";
	char output[256] = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB job = {.block_template = &tdata};
	size_t size;
	
	datum_test(!datum_stratum_block_needs_witness(&job, false));
	tdata.default_witness_commitment[0] = '1';
	datum_test(datum_stratum_block_needs_witness(&job, false));
	datum_test(!datum_stratum_block_needs_witness(&job, true));
	datum_test(!datum_stratum_block_needs_witness(NULL, false));
	
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, sizeof(stripped), true);
	output[size] = 0;
	datum_test(size == (sizeof(stripped) + 36) * 2);
	datum_test(!strncmp(output, "0100000000010102", 16));
	datum_test(!strncmp(output + 16, zero_witness, sizeof(zero_witness) - 1));
	datum_test(!strcmp(output + 16 + sizeof(zero_witness) - 1, "00000000"));
	
	memset(output, 0, sizeof(output));
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), witnessed, sizeof(witnessed), true);
	datum_test(size == sizeof(witnessed) * 2);
	datum_test(!strncmp(output, "010000000001010200000000", size));
	
	memset(output, 0, sizeof(output));
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, sizeof(stripped), false);
	datum_test(size == sizeof(stripped) * 2);
	datum_test(!strncmp(output, "01000000010200000000", size));
	datum_test(!datum_stratum_coinbase_for_block_hex(
		output, (sizeof(stripped) + 36) * 2 - 1, stripped, sizeof(stripped), true));
	datum_test(!datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, 7, true));
}

static void datum_stratum_string_request_id_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	char authorize[] =
		"{\"id\":\"authorize-17\",\"method\":\"mining.authorize\","
		"\"params\":[\"hardware.worker\",\"password\"]}";
	char authorize_numeric[] =
		"{\"id\":18,\"method\":\"mining.authorize\","
		"\"params\":[\"hardware.worker\",\"password\"]}";
	char unknown[] =
		"{\"id\":\"unknown-19\",\"method\":\"mining.unknown\",\"params\":[]}";
	char oversized[512];
	
	client.app_client_data = &miner;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize) == 0);
	datum_test(miner.authorized);
	datum_test(!strcmp(miner.last_auth_username, "hardware.worker"));
	datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n", client.out_buf));
	datum_test(miner.request_id_json[0] == 0);
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize_numeric) == 0);
	datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":18,\"result\":true}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":null,\"id\":18,\"result\":true}\n", client.out_buf));
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, unknown) == 0);
	datum_test(client.out_buf == (int)strlen(
		"{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n",
		client.out_buf));
	datum_test(miner.request_id_json[0] == 0);
	snprintf(oversized, sizeof(oversized),
		"{\"id\":\"%0130d\",\"method\":\"mining.authorize\",\"params\":[]}", 0);
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, oversized) == -4);
}

static void datum_stratum_minimum_difficulty_configure_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	char configure[] =
		"{\"id\":20,\"method\":\"mining.configure\","
		"\"params\":[[\"minimum-difficulty\"],{}]}";
	static const char expected[] =
		"{\"error\":null,\"id\":20,\"result\":{\"minimum-difficulty\":false}}\n";
	
	client.app_client_data = &miner;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, configure) == 0);
	datum_test(client.out_buf == (int)strlen(expected));
	datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
}


void datum_stratum_mod_username_tests() {
	const char * const s_umods = "{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3},\":)\":{\"\":0.5},\"a.c\":{\"addrD\":1.0}}";
	json_error_t err;
	json_t * const j_umods = JSON_LOADS(s_umods, &err);
	assert(j_umods);
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_umods, false);
	assert(ret == 1);
	json_decref(j_umods);
	datum_config.stratum_username_mod = umods;
	
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s, *modname;
	const char *res, *a1, *a2;
	
	strcpy(pool_addr, "dummy");
	
	s = "def~G";
	modname = &s[4];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1) == s);
	
	s = "def~x";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 1) == pool_addr);
	
	s = "def~abc";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	if (0 == strcmp(res, "addrB")) {  // jansson doesn't order keys'
		a1 = "addrB";
		a2 = "addrC";
	} else {
		a1 = "addrC";
		a2 = "addrB";
	}
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3);
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3);
	datum_test(0 == strcmp(res, a2));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3);
	datum_test(0 == strcmp(res, a2));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~abc";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~:)";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	memset(buf, 0, 7);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x7fff, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x8000, modname, 2) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 2) == pool_addr);
	
	s = "xyz~a.c";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	datum_test(0 == strcmp(res, "addrD"));
	
	// Intentionally overflow buf with address: we lose the worker name, but get the full address via its umod buffer
	s = "def.ghi~x";
	modname = &s[8];
	memset(buf, 0x0e, 8);
	res = datum_stratum_mod_username(s, buf, 2, 0, modname, 1);
	datum_test(res != buf);
	datum_test(res != pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	res = datum_stratum_mod_username(s, buf, 2, 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, 2, 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0xffff, modname, 1) == pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(buf[6] == 0x0e);
	res = datum_stratum_mod_username(s, buf, 6, 0, modname, 1);
	datum_test(res == buf);
	datum_test(res != pool_addr);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 1) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "addrA."));
	memset(buf, 0x0e, 10);
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 1) == buf);
	datum_test(buf[9] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.g"));
	memset(buf, 0x0e, 11);
	datum_test(datum_stratum_mod_username(s, buf, 9, 0, modname, 1) == buf);
	datum_test(buf[10] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.gh"));
	memset(buf, 0x0e, 12);
	datum_test(datum_stratum_mod_username(s, buf, 10, 0, modname, 1) == buf);
	datum_test(buf[11] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.ghi"));
	s = "def.ghi~:)";
	modname = &s[8];
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0, modname, 2) == buf);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "d"));
	datum_test(datum_stratum_mod_username(s, buf, 6, 0, modname, 2) == buf);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "def.g"));
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 2) == buf);
	datum_test(buf[7] == 0x0e);
	datum_test(0 == strcmp(res, "def.gh"));
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 2) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "def.ghi"));
}

void datum_stratum_tests(void) {
	datum_stratum_mod_username_tests();
	datum_stratum_minimum_difficulty_configure_tests();
	datum_stratum_string_request_id_tests();
	datum_blake2b_coinbase_selection_tests();
	datum_blake2b_h_not_zero_tests();
	datum_blake2b_malformed_submit_hex_tests();
	datum_blake2b_client_pot_commitment_tests();
	datum_blake2b_unmasked_block_tests();
	datum_stratum_abw_block_request_tests();
	datum_blake2b_refresh_time_offset_tests();
	datum_block_coinbase_witness_tests();
}
