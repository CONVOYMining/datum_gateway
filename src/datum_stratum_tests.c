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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_pow.h"
#include "datum_protocol.h"
#include "datum_queue.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_utils.h"

void stratum_calculate_merkle_branches(T_DATUM_STRATUM_JOB *s);
int client_mining_submit(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);
bool stratum_job_coinbaser_ready(T_DATUM_STRATUM_THREADPOOL_DATA *sdata, T_DATUM_STRATUM_JOB *job);

extern uint64_t stratum_latest_empty_complete_count;
extern bool stratum_latest_empty_ready_for_full;
extern uint64_t stratum_latest_empty_job_index;
extern uint64_t stratum_latest_empty_sent_count;

static void datum_blake2b_refresh_time_offset_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	
	/* A job snapshots whether miners may submit a time offset. */
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	job.block_template = &tdata;
	tdata.curtime = 2000000000;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	datum_test(job.blake2b_flags == DATUM_BLAKE2B_USE_TIME_OFFSET);
	
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
	T_DATUM_MINER_DATA miner = {
		.subscribed = true,
	};
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
	job.coinbase[0].coinb1_len = 2;
	job.coinbase[0].coinb1_bin[0] = job.coinbase[0].coinb1_bin[1] = 0xff;
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

static void datum_stratum_test_coinbaser_locks(void) {
	// Normally set up when the stratum server starts
	if (atomic_load_explicit(&need_coinbaser_rwlocks_init_done, memory_order_acquire)) return;
	for (int i = 0; i < MAX_STRATUM_JOBS; ++i) {
		pthread_rwlock_init(&need_coinbaser_rwlocks[i], NULL);
	}
	atomic_store_explicit(&need_coinbaser_rwlocks_init_done, true, memory_order_release);
}

static void datum_stratum_coinbaser_ready_tests(void) {
	T_DATUM_STRATUM_THREADPOOL_DATA * const sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	
	datum_test(sdata != NULL);
	if (!sdata) return;
	datum_stratum_test_coinbaser_locks();
	job.tsms = 1000000;
	job.need_coinbaser = true;
	
	// Still waiting on the coinbaser
	sdata->loop_tsms = job.tsms + 4000;
	datum_test(!stratum_job_coinbaser_ready(sdata, &job));
	datum_test(!sdata->full_coinbase_ready);
	
	// Gave up waiting after 5 seconds
	sdata->loop_tsms = job.tsms + 5001;
	datum_test(stratum_job_coinbaser_ready(sdata, &job));
	datum_test(!sdata->full_coinbase_ready);
	
	// A coinbaser that is here gets used, even if the job is first looked at after 5 seconds
	job.need_coinbaser = false;
	datum_test(stratum_job_coinbaser_ready(sdata, &job));
	datum_test(sdata->full_coinbase_ready);
	
	sdata->full_coinbase_ready = false;
	sdata->loop_tsms = job.tsms + 1;
	datum_test(stratum_job_coinbaser_ready(sdata, &job));
	datum_test(sdata->full_coinbase_ready);
	
	free(sdata);
}

static void datum_stratum_new_thread_job_tests(void) {
	// T_DATUM_THREAD_DATA holds MAX_CLIENTS_THREAD client buffers (hundreds of MB), but only its own
	// fields and the first client slot are touched here, and calloc'd memory normally gets backed as used
	T_DATUM_THREAD_DATA * const thread = calloc(1, sizeof(*thread));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sdata = calloc(1, sizeof(*sdata));
	T_DATUM_SOCKET_APP app = {0};
	T_DATUM_MINER_DATA miner;
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB job = {0};
	const global_config_t saved_config = datum_config;
	const int saved_latest_index = global_latest_stratum_job_index;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[0];
	char subscribe[] = "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}";
	
	datum_test(thread != NULL);
	datum_test(sdata != NULL);
	if (!(thread && sdata)) {
		free(thread);
		free(sdata);
		return;
	}
	datum_stratum_test_coinbaser_locks();
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;
	datum_config.bitcoind_work_update_seconds = 40;
	
	// The current job already has its coinbaser, and is older than the 5 second fallback
	tdata.version = 0x20000000;
	tdata.height = 12345;
	tdata.bits_uint = 0x1d00ffff;
	job.block_template = &tdata;
	job.job_state = JOB_STATE_FULL_NORMAL_WAIT_COINBASER;
	job.tsms = current_time_millis() - 10000;
	strcpy(job.job_id, "0000000000c0de");
	job.target_pot_index = 4;
	for (int i = 0; i < MAX_COINBASE_TYPES; ++i) {
		job.coinbase[i].coinb1_len = 20;
		job.coinbase[i].coinb2_len = 8;
		memset(job.coinbase[i].coinb1_bin, 0x11 + i, 20);
		memset(job.coinbase[i].coinb2_bin, 0x22, 8);
	}
	global_cur_stratum_jobs[0] = &job;
	global_latest_stratum_job_index = 0;
	
	// A new stratum thread starts, and loops once before its first client subscribes
	app.max_threads = 1;
	app.max_clients_thread = 1;
	thread->app = &app;
	thread->app_thread_data = sdata;
	datum_stratum_v1_socket_thread_init(thread);
	datum_stratum_v1_socket_thread_loop(thread);
	datum_test(sdata->cur_stratum_job == &job);
	datum_test(sdata->full_coinbase_ready);
	
	T_DATUM_CLIENT_DATA * const client = &thread->client_data[0];
	client->datum_thread = thread;
	client->app_client_data = &miner;
	datum_stratum_v1_socket_thread_client_new(client);
	datum_test(datum_stratum_v1_socket_thread_client_cmd(client, subscribe) == 0);
	client->w_buffer[client->out_buf] = 0;
	
	// Its first job must use the full coinbase (class 4), not the pool-only one (class 0)
	const char * const notify = strstr(client->w_buffer, "\"mining.notify\"");
	datum_test(notify && strstr(notify, "[\"0000000000c0de04\","));
	
	T_DATUM_STRATUM_DUPES * const dupes = sdata->dupes;
	if (dupes) free(dupes->ptr);
	free(dupes);
	global_cur_stratum_jobs[0] = saved_job;
	global_latest_stratum_job_index = saved_latest_index;
	datum_config = saved_config;
	free(sdata);
	free(thread);
}

static void datum_stratum_new_thread_empty_work_tests(void) {
	T_DATUM_THREAD_DATA * const thread = calloc(1, sizeof(*thread));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sdata = calloc(1, sizeof(*sdata));
	T_DATUM_SOCKET_APP app = {0};
	T_DATUM_STRATUM_JOB job = {0};
	const global_config_t saved_config = datum_config;
	const int saved_latest_index = global_latest_stratum_job_index;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[0];
	const uint64_t saved_complete_count = stratum_latest_empty_complete_count;
	const bool saved_ready_for_full = stratum_latest_empty_ready_for_full;
	const uint64_t saved_empty_job_index = stratum_latest_empty_job_index;
	const uint64_t saved_sent_count = stratum_latest_empty_sent_count;
	
	datum_test(thread != NULL);
	datum_test(sdata != NULL);
	if (!(thread && sdata)) {
		free(thread);
		free(sdata);
		return;
	}
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;
	
	// Empty work for a new block is going out, as set up by update_stratum_job
	job.job_state = JOB_STATE_EMPTY_PLUS;
	global_cur_stratum_jobs[0] = &job;
	global_latest_stratum_job_index = 0;
	stratum_latest_empty_job_index = 0;
	stratum_latest_empty_ready_for_full = false;
	stratum_latest_empty_complete_count = 0;
	stratum_latest_empty_sent_count = 0;
	
	// A thread started now counts towards the threads that have to send it, so it must send
	// it too, or the full work for the block waits for the template thread's timeout
	app.max_threads = 1;
	app.max_clients_thread = 1;
	thread->app = &app;
	thread->app_thread_data = sdata;
	datum_stratum_v1_socket_thread_init(thread);
	datum_stratum_v1_socket_thread_loop(thread);
	datum_test(stratum_latest_empty_complete_count == 1);
	
	T_DATUM_STRATUM_DUPES * const dupes = sdata->dupes;
	if (dupes) free(dupes->ptr);
	free(dupes);
	stratum_latest_empty_job_index = saved_empty_job_index;
	stratum_latest_empty_ready_for_full = saved_ready_for_full;
	stratum_latest_empty_complete_count = saved_complete_count;
	stratum_latest_empty_sent_count = saved_sent_count;
	global_cur_stratum_jobs[0] = saved_job;
	global_latest_stratum_job_index = saved_latest_index;
	datum_config = saved_config;
	free(sdata);
	free(thread);
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


// A connection with its own thread data, for tests that drive one client directly.
static T_DATUM_CLIENT_DATA *datum_stratum_test_client(void) {
	T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
	T_DATUM_THREAD_DATA * const t = calloc(1, sizeof(T_DATUM_THREAD_DATA));
	assert(m && sd && c && t);
	m->sdata = sd;
	c->app_client_data = m;
	c->datum_thread = t;
	c->cid = 1;
	t->app_thread_data = sd;
	return c;
}

static void datum_stratum_test_client_free(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	free(c->datum_thread);
	free(m->sdata);
	free(m);
	free(c);
}

static const char *datum_stratum_test_take(T_DATUM_CLIENT_DATA *c) {
	c->w_buffer[c->out_buf] = 0;
	c->out_buf = 0;
	return c->w_buffer;
}

// The job of the share tests: pooled, without anti-withholding, a two-byte coinb1 (0xff 0xff)
// whose first byte is the coinbase target byte, any ntime accepted, and no block. A share for
// it needs a work hash whose top 32 bits are zero (H-not-zero), about 2^32 hashes to find, so
// the tests use nonces found for this job, extranonce2 deadbeef00000000 and ntime 0, one for
// each target byte they need.
#define SHARE_EXTRANONCE2 "deadbeef00000000"
#define SHARE_NONCE_POT0 "abbcc51400000007"
#define SHARE_NONCE_POT20 "1cbc299806000000"
static T_DATUM_STRATUM_JOB *datum_stratum_test_share_job(void) {
	T_DATUM_STRATUM_JOB * const j = calloc(1, sizeof(*j));
	T_DATUM_TEMPLATE_DATA * const t = calloc(1, sizeof(*t));
	assert(j && t);
	j->is_datum_job = true;
	j->block_template = t;
	j->target_pot_index = 0;
	j->coinbase[0].coinb1_len = 2;
	j->coinbase[0].coinb1_bin[0] = j->coinbase[0].coinb1_bin[1] = 0xff;
	strcpy(j->job_id, "0000000000c0de");
	return j;
}

static void datum_stratum_test_share_job_free(T_DATUM_STRATUM_JOB *j) {
	free(j->block_template);
	free(j);
}

// Captures what client_mining_submit sends to the pool, via the real POW queue.
extern DATUM_QUEUE pow_queue;
static int datum_stratum_test_pow_handler(void *arg) { (void)arg; return 0; }

static int datum_stratum_test_pow_count(void) {
	return pow_queue.queue_next[pow_queue.active_buffer];
}

static const T_DATUM_PROTOCOL_POW *datum_stratum_test_pow_last(void) {
	const int buf = pow_queue.active_buffer;
	const int n = pow_queue.queue_next[buf];
	return n ? &((T_DATUM_PROTOCOL_POW *)pow_queue.buffer[buf])[n - 1] : NULL;
}

// A block submission is queued for the submitblock thread, which doesn't run in the tests;
// take it back, or the submitblock tests that follow wait for it forever.
extern pthread_mutex_t submitblock_mutex;
extern int submit_block_triggered;
extern const char *submitblock_ptr;
extern bool submitblock_ptr_owned;
static bool datum_stratum_test_discard_submitblock(void) {
	pthread_mutex_lock(&submitblock_mutex);
	const bool queued = submit_block_triggered && submitblock_ptr;
	if (submitblock_ptr_owned) free((void *)submitblock_ptr);
	submitblock_ptr = NULL;
	submitblock_ptr_owned = false;
	submit_block_triggered = 0;
	pthread_mutex_unlock(&submitblock_mutex);
	return queued;
}

// Settings an accepted share needs (vardiff runs on each one).
static void datum_stratum_test_submit_config(void) {
	datum_config.stratum_v1_share_stale_seconds = 120;
	datum_config.bitcoind_work_update_seconds = 40;
	datum_config.stratum_v1_vardiff_min = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 8;
	datum_config.stratum_v1_vardiff_quickdiff_count = 8;
	datum_config.stratum_v1_vardiff_quickdiff_delta = 8;
}

// A subscribed connection on job index 0, served difficulty 1, ready for client_mining_submit.
static T_DATUM_CLIENT_DATA *datum_stratum_test_submit_client(T_DATUM_STRATUM_JOB *job) {
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_client();
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	datum_stratum_dupes_init(m->sdata);
	m->sdata->loop_tsms = 1000000;
	job->tsms = m->sdata->loop_tsms;
	m->subscribed = true;
	m->current_diff = m->last_sent_diff = 1;
	m->stratum_job_diffs[0] = 1;
	datum_test(datum_blake2b_share_target(m->stratum_job_targets[0], 0));
	return c;
}

static void datum_stratum_test_submit_client_free(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	T_DATUM_STRATUM_DUPES * const dupes = m->sdata->dupes;
	free(dupes->ptr);
	free(dupes);
	datum_stratum_test_client_free(c);
}

// A fresh dupe table, so the same share can be submitted again.
static void datum_stratum_test_fresh_dupes(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	T_DATUM_STRATUM_DUPES * const dupes = m->sdata->dupes;
	free(dupes->ptr);
	free(dupes);
	datum_stratum_dupes_init(m->sdata);
}

static int datum_stratum_test_submit(T_DATUM_CLIENT_DATA *c, const char *job_id, const char *nonce) {
	char req[200];
	snprintf(req, sizeof(req), "[\"w\", \"%s\", \"" SHARE_EXTRANONCE2 "\", \"0000000000000000\", \"%s\"]", job_id, nonce);
	json_error_t err;
	json_t * const params = json_loads(req, 0, &err);
	assert(params);
	const int ret = client_mining_submit(c, 1, params);
	json_decref(params);
	return ret;
}

// A share for an older job, once a harder difficulty is served, gets the served difficulty if
// it meets it and nothing otherwise.
static void datum_stratum_share_credit_tests(void) {
	uint8_t t_easy[32], t_hard[32];
	datum_test(datum_blake2b_share_target(t_easy, floorPoT(1024)));
	datum_test(datum_blake2b_share_target(t_hard, floorPoT(16384)));
	datum_test(datum_stratum_share_credit_diff(t_hard, 1024, 16384) == 16384);
	datum_test(datum_stratum_share_credit_diff(t_easy, 1024, 16384) == 0);
	datum_test(datum_stratum_share_credit_diff(t_easy, 1024, 1024) == 1024);
	datum_test(datum_stratum_share_credit_diff(t_hard, 16384, 1024) == 16384);
	
	// Through client_mining_submit: credited at the job's difficulty, and after a step up to a
	// difficulty the share doesn't meet, accepted and credited at nothing.
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 1 && m->share_diff_accepted == 1);
	datum_test(datum_stratum_test_pow_count() == 1);
	
	datum_stratum_test_fresh_dupes(c);
	m->current_diff = m->last_sent_diff = UINT64_C(1) << 22;
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 2 && m->share_diff_accepted == 1);
	// and, credited at nothing, it isn't counted toward vardiff's rate (the first share was).
	datum_test(m->share_count_since_snap == 1 && m->share_count_below_diff_since_snap == 1);
	
	datum_stratum_test_submit_client_free(c);
	datum_test(datum_queue_free(&pow_queue) == 0);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_share_job_free(job);
	datum_config = saved;
}

// Vardiff measures the rate at the difficulty now served.
static void datum_stratum_vardiff_measure_tests(void) {
	const global_config_t saved = datum_config;
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_vardiff_quickdiff_count = 8;
	datum_config.stratum_v1_vardiff_quickdiff_delta = 8;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_client();
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->loop_tsms = 1000000;
	m->current_diff = m->last_sent_diff = 8192;
	
	// A new difficulty starts a new measurement.
	m->share_count_since_snap = 250;
	m->share_count_below_diff_since_snap = 3;
	m->current_diff = 16384;
	datum_test(send_mining_set_difficulty(c) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.set_difficulty\",\"params\":[16383.75]") != NULL);
	datum_test(m->share_count_since_snap == 0 && m->share_count_below_diff_since_snap == 0);
	
	// A share credited at nothing is not counted; one credited at the served difficulty is.
	datum_stratum_count_vardiff_share(m, 0);
	datum_test(m->share_count_since_snap == 0 && m->share_count_below_diff_since_snap == 1);
	datum_stratum_count_vardiff_share(m, 16384);
	datum_test(m->share_count_since_snap == 1 && m->share_diff_since_snap == 16384);
	
	// Uncounted shares alone don't trigger a quickdiff, and a minute of only them is not
	// silence: a fresh minute starts and the count is cleared...
	reset_vardiff_stats(c);
	m->share_snap_tsms = m->sdata->loop_tsms - 2000;
	for (int i = 0; i < 9; ++i) datum_stratum_count_vardiff_share(m, 0);
	stratum_update_vardiff(c, false);
	datum_test(m->current_diff == 16384);
	m->share_snap_tsms = m->sdata->loop_tsms - 70000;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);
	datum_test(m->share_count_below_diff_since_snap == 0);
	// ...and a miner that then finds nothing is stepped down a minute later, as before.
	m->share_snap_tsms = m->sdata->loop_tsms - 70000;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 8192);
	
	datum_stratum_test_client_free(c);
	datum_config = saved;
}

// A quickdiff (Q) share is only for the job its quickdiff notify was sent for, and the check
// comes after the block check, so a block the Gateway can recognise in such a share is still
// submitted. One nonce serves every share: a refused Q share never reaches the dupe check.
static void datum_stratum_quickdiff_job_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->quickdiff_value = 1;
	datum_test(datum_blake2b_share_target(m->quickdiff_target, 0));
	
	// A Q share for another job is refused, and nothing is sent upstream.
	m->quickdiff_job_index = 7;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "[20,\"unknown-work\",null]") != NULL);
	datum_test(m->share_count_rejected == 1 && m->share_count_accepted == 0);
	datum_test(datum_stratum_test_pow_count() == 0);
	
	// A Q share for its own job is accepted and forwarded.
	m->quickdiff_job_index = 0;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_rejected == 1 && m->share_count_accepted == 1);
	datum_test(datum_stratum_test_pow_count() == 1 && !datum_stratum_test_pow_last()->is_block);
	
	// A block in a Q share for another job is still submitted, to the pool and to the node,
	// then the share is refused.
	memset(job->block_target, 0xff, sizeof(job->block_target));
	m->quickdiff_job_index = 7;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(datum_stratum_test_discard_submitblock());
	datum_test(strstr(datum_stratum_test_take(c), "[20,\"unknown-work\",null]") != NULL);
	datum_test(m->share_count_rejected == 2 && m->share_count_accepted == 1);
	datum_test(datum_stratum_test_pow_count() == 2 && datum_stratum_test_pow_last()->is_block);
	
	datum_stratum_test_submit_client_free(c);
	datum_test(datum_queue_free(&pow_queue) == 0);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_share_job_free(job);
	datum_config = saved;
}

// The quickdiff is bound to the job it was sent for whatever its index: here job index 1,
// through send_mining_notify. A Q share for it is accepted, and one naming job 0 is refused.
static void datum_stratum_quickdiff_job_index_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job0 = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const job1 = datum_stratum_test_share_job();
	strcpy(job1->job_id, "0000000000c0df");
	job1->global_index = 1;
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	T_DATUM_STRATUM_JOB * const saved_job1 = global_cur_stratum_jobs[1];
	global_cur_stratum_jobs[0] = job0;
	global_cur_stratum_jobs[1] = job1;
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job0);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	job1->tsms = m->sdata->loop_tsms;
	m->sdata->cur_stratum_job = job1;
	m->last_sent_stratum_job_index = 1;
	
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q0000000000c0df00\"") != NULL);
	datum_test(m->quickdiff_job_index == 1 && m->quickdiff_value == 1);
	
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "[20,\"unknown-work\",null]") != NULL);
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0df00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_rejected == 1 && m->share_count_accepted == 1);
	
	datum_stratum_test_submit_client_free(c);
	datum_test(datum_queue_free(&pow_queue) == 0);
	global_cur_stratum_jobs[0] = saved_job0;
	global_cur_stratum_jobs[1] = saved_job1;
	datum_stratum_test_share_job_free(job0);
	datum_stratum_test_share_job_free(job1);
	datum_config = saved;
}

// A Q share not bound to the current quickdiff is rebuilt with the current quickdiff's target
// byte, so it fails H-not-zero, and is answered as unknown work at the difficulty now served,
// not as H-not-zero. A bound share failing H-not-zero is refused for what it is.
static void datum_stratum_unbound_quickdiff_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->current_diff = m->last_sent_diff = 64;
	m->quickdiff_value = 16;
	datum_test(datum_blake2b_share_target(m->quickdiff_target, 4));
	
	// With no quickdiff sent at all.
	m->quickdiff_value = 0;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "[20,\"unknown-work\",null]") != NULL);
	datum_test(m->share_count_rejected == 1 && m->share_diff_rejected == 64);
	
	// For another job, rebuilt with target byte 4 rather than the 0 it was found for.
	m->quickdiff_value = 16;
	m->quickdiff_job_index = 7;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "[20,\"unknown-work\",null]") != NULL);
	datum_test(m->share_count_rejected == 2 && m->share_diff_rejected == 128);
	
	// Bound to the current quickdiff: refused as H-not-zero, at the quickdiff difficulty.
	m->quickdiff_job_index = 0;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "[23,\"H-not-zero\",null]") != NULL);
	datum_test(m->share_count_rejected == 3 && m->share_diff_rejected == 144);
	
	datum_stratum_test_submit_client_free(c);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_share_job_free(job);
	datum_config = saved;
}

// A quickdiff for a job the miner hasn't been sent yet sends only the difficulty. The job then
// arrives once, as a regular job at the new difficulty, and the job the miner holds keeps its
// stored target for shares in flight.
static void datum_stratum_pending_job_quickdiff_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job0 = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const job1 = datum_stratum_test_share_job();
	strcpy(job1->job_id, "0000000000c0df");
	job1->global_index = 1;
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	T_DATUM_STRATUM_JOB * const saved_job1 = global_cur_stratum_jobs[1];
	global_cur_stratum_jobs[0] = job0;
	global_cur_stratum_jobs[1] = job1;
	for (int solo = 0; solo <= 1; ++solo) {
		T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job0);
		T_DATUM_MINER_DATA * const m = c->app_client_data;
		job0->is_datum_job = job1->is_datum_job = !solo;
		m->sdata->cur_stratum_job = job1;
		m->last_sent_stratum_job_index = 0;
		m->current_diff = 16384;
		datum_test(send_mining_notify(c, true, true, false) == 0);
		const char *out = datum_stratum_test_take(c);
		datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[16383.75]") != NULL);
		datum_test(strstr(out, "mining.notify") == NULL);
		datum_test(m->quickdiff_active && !m->quickdiff_value);
		datum_test(m->stratum_job_diffs[0] == 1 && m->stratum_job_diffs[1] == 0);
		datum_test(send_mining_notify(c, false, false, false) == 0);
		out = datum_stratum_test_take(c);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"0000000000c0df00\"") != NULL);
		datum_test(!m->quickdiff_active);
		datum_test(m->last_sent_stratum_job_index == 1 && m->stratum_job_diffs[1] == 16384);
		datum_test(m->stratum_job_diffs[0] == 1);
		datum_stratum_test_submit_client_free(c);
	}
	global_cur_stratum_jobs[0] = saved_job0;
	global_cur_stratum_jobs[1] = saved_job1;
	datum_stratum_test_share_job_free(job0);
	datum_stratum_test_share_job_free(job1);
	datum_config = saved;
}

// The coinb1 hex a miner must be sent for the share job at this committed target byte.
static void datum_stratum_test_coinb1_hex(T_DATUM_STRATUM_JOB *j, unsigned char pot, char *hex) {
	unsigned char commitment[32], coinb1[39];
	hex[0] = 0;
	if (!datum_stratum_job_blake2b_commitment(j, &j->coinbase[0], false, pot, commitment, coinb1)) return;
	for (size_t i = 0; i < sizeof(coinb1); ++i) uchar_to_hex(&hex[i << 1], coinb1[i]);
	hex[sizeof(coinb1) << 1] = 0;
}

// The notify for the share job as sent: its coinb1 commits to 2^commit_pot, and its nbits hint
// is the served target 2^served_pot.
static bool datum_stratum_test_notify_is(const char *out, T_DATUM_STRATUM_JOB *j, unsigned char commit_pot, unsigned char served_pot) {
	char coinb1[128], nbits[16];
	datum_stratum_test_coinb1_hex(j, commit_pot, coinb1);
	snprintf(nbits, sizeof(nbits), "\"%8.8x\"", datum_blake2b_share_nbits(served_pot));
	return coinb1[0] && strstr(out, coinb1) && strstr(out, nbits);
}

// A connection to pooled work whose pool minimum, 2^20, is far above the local floor (1).
static void datum_stratum_vardiff_below_pool_min_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->cur_stratum_job = job;
	const char *out;
	
	// Off (the default): the miner is raised to the pool minimum and committed there, as before,
	// with no separate commitment, for a job or a quickdiff.
	datum_config.stratum_v1_vardiff_below_pool_min = false;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[1048560]") != NULL);
	datum_test(datum_stratum_test_notify_is(out, job, 20, 20));
	datum_test(m->stratum_job_diffs[0] == (UINT64_C(1) << 20) && m->stratum_job_commit_pots[0] == 0);
	m->current_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
	datum_test(datum_stratum_test_notify_is(out, job, 22, 22));
	datum_test(m->quickdiff_commit_pot == 0);
	
	// On: the miner keeps its own difficulty, and the work is still committed to the minimum.
	// nbits, a hint to the hasher, is the served target.
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "1048560") == NULL);
	datum_test(datum_stratum_test_notify_is(out, job, 20, 0));
	datum_test(m->stratum_job_diffs[0] == 1 && m->stratum_job_commit_pots[0] == 20);
	
	// Served exactly at the minimum: committed at its own difficulty, with no separate commitment.
	m->current_diff = UINT64_C(1) << 20;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(datum_stratum_test_notify_is(datum_stratum_test_take(c), job, 20, 20));
	datum_test(m->stratum_job_commit_pots[0] == 0);
	
	// Served above the minimum: committed at the served difficulty, as without the option.
	m->current_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(datum_stratum_test_notify_is(datum_stratum_test_take(c), job, 22, 22));
	datum_test(m->stratum_job_commit_pots[0] == 0);
	
	// A quickdiff that lifts the miner above the minimum is committed at its own difficulty,
	// though the job it is for was committed at the minimum.
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	(void)datum_stratum_test_take(c);
	datum_test(m->stratum_job_commit_pots[0] == 20);
	m->current_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
	datum_test(datum_stratum_test_notify_is(out, job, 22, 22));
	datum_test(m->quickdiff_commit_pot == 0 && m->stratum_job_commit_pots[0] == 20);
	
	// A new pool minimum applies from the next job, and from a quickdiff below it, which is
	// then new work committed at the new minimum.
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	(void)datum_stratum_test_take(c);
	datum_config.override_vardiff_min = UINT64_C(1) << 21;
	m->current_diff = 16384;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
	datum_test(datum_stratum_test_notify_is(out, job, 21, 14));
	datum_test(m->quickdiff_commit_pot == 21 && m->stratum_job_commit_pots[0] == 20);
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(datum_stratum_test_notify_is(datum_stratum_test_take(c), job, 21, 0));
	datum_test(m->stratum_job_commit_pots[0] == 21);
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	
	// Switched off at runtime: the next job is raised to the minimum, with no separate
	// commitment, and so is the next quickdiff.
	datum_config.stratum_v1_vardiff_below_pool_min = false;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[1048560]") != NULL);
	datum_test(datum_stratum_test_notify_is(out, job, 20, 20));
	datum_test(m->stratum_job_commit_pots[0] == 0);
	
	// Solo work is never committed apart from the served difficulty.
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	job->is_datum_job = false;
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	(void)datum_stratum_test_take(c);
	datum_test(m->stratum_job_diffs[0] == 1 && m->stratum_job_commit_pots[0] == 0);
	
	// The forwarding decision.
	{
		uint8_t served[32], committed[32];
		datum_test(datum_blake2b_share_target(served, 0));
		datum_test(datum_blake2b_share_target(committed, 20));
		datum_test(datum_stratum_share_forwardable(served, 0));
		datum_test(datum_stratum_share_forwardable(committed, 20));
		datum_test(!datum_stratum_share_forwardable(served, 20));
	}
	
	datum_stratum_test_submit_client_free(c);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_share_job_free(job);
	datum_config = saved;
}

// Through client_mining_submit, with a share found for the job committed at 2^20. Served at 1,
// it is accepted, credited at 1, and kept local; served at the minimum (committed there, with
// no separate commitment), it is accepted and sent to the pool with target byte 20. The share
// found for the job at target byte 0 is not work for the job committed at 2^20.
static void datum_stratum_submit_forwarding_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	m->stratum_job_commit_pots[0] = 20;
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "[23,\"H-not-zero\",null]") != NULL);
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", SHARE_NONCE_POT20) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 1 && m->share_diff_accepted == 1);
	datum_test(datum_stratum_test_pow_count() == 0);
	
	// A Q share committed at the minimum likewise.
	datum_stratum_test_fresh_dupes(c);
	m->quickdiff_value = 1;
	m->quickdiff_commit_pot = 20;
	m->quickdiff_job_index = 0;
	datum_test(datum_blake2b_share_target(m->quickdiff_target, 0));
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT20) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 2 && datum_stratum_test_pow_count() == 0);
	
	// A Q share's commitment is its own, not its job's: a quickdiff committed at its own
	// difficulty, for a job committed at the minimum, rebuilds with the quickdiff's byte.
	datum_stratum_test_fresh_dupes(c);
	m->stratum_job_commit_pots[0] = 20;
	m->quickdiff_commit_pot = 0;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", SHARE_NONCE_POT0) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 3 && datum_stratum_test_pow_count() == 1);
	(void)datum_queue_free(&pow_queue);
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	
	// Served at the minimum. (Its target is opened up: no share meeting 2^20 can be found in a
	// test.)
	datum_stratum_test_fresh_dupes(c);
	m->stratum_job_commit_pots[0] = 0;
	m->current_diff = m->last_sent_diff = m->stratum_job_diffs[0] = UINT64_C(1) << 20;
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", SHARE_NONCE_POT20) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 4);
	datum_test(datum_stratum_test_pow_count() == 1 && datum_stratum_test_pow_last()->target_byte == 20);
	
	datum_stratum_test_submit_client_free(c);
	datum_test(datum_queue_free(&pow_queue) == 0);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_share_job_free(job);
	datum_config = saved;
}

// A quickdiff on the job the miner holds, when that work is committed at the pool minimum and
// the quickdiff would carry the same target byte, sends only the new difficulty: a Q job would be
// the same work. It is sent whenever its work would differ, and always with the option off.
static void datum_stratum_repeat_quickdiff_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_share_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->cur_stratum_job = job;
	const char *out;
	
	// Served-only: just the new difficulty, and the job's entries stay as they were...
	datum_test(send_mining_notify(c, true, false, false) == 0);
	(void)datum_stratum_test_take(c);
	m->current_diff = 16384;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[16383.75]") != NULL);
	datum_test(strstr(out, "mining.notify") == NULL);
	datum_test(m->quickdiff_active && !m->quickdiff_value);
	datum_test(m->stratum_job_diffs[0] == 1 && m->stratum_job_commit_pots[0] == 20);
	
	// ...so a share the miner had in flight for it is still accepted (and kept local).
	{
		datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
		datum_test(datum_stratum_test_submit(c, "0000000000c0de00", SHARE_NONCE_POT20) == 0);
		datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
		datum_test(datum_stratum_test_pow_count() == 0);
		datum_test(datum_queue_free(&pow_queue) == 0);
	}
	
	// The next regular notify carries the new difficulty, still committed at the minimum.
	datum_test(send_mining_notify(c, false, false, false) == 0);
	datum_test(datum_stratum_test_notify_is(datum_stratum_test_take(c), job, 20, 14));
	datum_test(!m->quickdiff_active && m->stratum_job_diffs[0] == 16384);
	
	// Served exactly at the minimum: committed at its own difficulty, which is the same byte.
	m->current_diff = UINT64_C(1) << 20;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "mining.notify") == NULL);
	
	// Above the minimum: a different byte, so a Q job, after which the miner holds work that
	// isn't committed apart, and a further quickdiff is sent as before.
	m->current_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q") != NULL);
	datum_test(m->last_sent_commit_pot == 0);
	
	// The same job index with a different job ID (the table wrapped) is different work.
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	(void)datum_stratum_test_take(c);
	job->job_id[7] = '1';
	m->current_diff = 16384;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q0000000100c0de00\"") != NULL);
	job->job_id[7] = '0';
	
	// After the subsidy-only work of a new block, the full coinbase is different work.
	job->subsidy_only_coinbase = job->coinbase[0];
	job->subsidy_only_coinbase.coinb1_bin[1] ^= 0xaa;
	m->current_diff = 1;
	datum_test(send_mining_notify(c, true, false, true) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"N") != NULL);
	datum_test(m->last_sent_commit_pot == 20);
	m->current_diff = 16384;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q") != NULL);
	
	// With the option off, a quickdiff is sent as before.
	datum_config.stratum_v1_vardiff_below_pool_min = false;
	m->current_diff = UINT64_C(1) << 20;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	(void)datum_stratum_test_take(c);
	m->current_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q") != NULL);
	
	datum_stratum_test_submit_client_free(c);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_share_job_free(job);
	datum_config = saved;
}

// datum.capabilities reports the features this Gateway has and whether each is on, as valid
// JSON, for an integer or a string request id.
static void datum_stratum_capabilities_tests(void) {
	const global_config_t saved = datum_config;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_client();
	// Not mining pooled, a pool minimum still held from before is reported as 0.
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	for (int on = 0; on <= 1; ++on) {
		char req[] = "{\"id\":7,\"method\":\"datum.capabilities\",\"params\":[]}";
		datum_config.stratum_v1_vardiff_below_pool_min = on;
		datum_test(datum_stratum_v1_socket_thread_client_cmd(c, req) == 0);
		const char * const out = datum_stratum_test_take(c);
		json_error_t err;
		json_t * const reply = json_loads(out, JSON_DISABLE_EOF_CHECK, &err);
		datum_test(reply != NULL);
		json_t * const result = reply ? json_object_get(reply, "result") : NULL;
		json_t * const feats = result ? json_object_get(result, "features") : NULL;
		datum_test(reply && json_integer_value(json_object_get(reply, "id")) == 7);
		datum_test(reply && json_is_null(json_object_get(reply, "error")));
		datum_test(feats && json_is_true(json_object_get(feats, "reject_tls_probe")));
		datum_test(feats && json_is_boolean(json_object_get(feats, "vardiff_below_pool_min")) &&
			json_boolean_value(json_object_get(feats, "vardiff_below_pool_min")) == (bool)on);
		datum_test(result && json_string_value(json_object_get(result, "algo")) &&
			!strcmp(json_string_value(json_object_get(result, "algo")), "blake2b"));
		datum_test(result && json_string_value(json_object_get(result, "gateway")) &&
			!strcmp(json_string_value(json_object_get(result, "gateway")), DATUM_PROTOCOL_VERSION));
		datum_test(result && json_is_false(json_object_get(result, "pooled")));
		datum_test(result && json_is_integer(json_object_get(result, "pool_min_diff")) &&
			json_integer_value(json_object_get(result, "pool_min_diff")) == 0);
		json_decref(reply);
	}
	{
		char req[] = "{\"id\":\"caps\",\"method\":\"datum.capabilities\",\"params\":[]}";
		datum_test(datum_stratum_v1_socket_thread_client_cmd(c, req) == 0);
		datum_test(strncmp(datum_stratum_test_take(c), "{\"error\":null,\"id\":\"caps\",\"result\":{", 36) == 0);
	}
	datum_stratum_test_client_free(c);
	datum_config = saved;
}

void datum_stratum_tests(void) {
	datum_stratum_capabilities_tests();
	datum_stratum_repeat_quickdiff_tests();
	datum_stratum_vardiff_below_pool_min_tests();
	datum_stratum_submit_forwarding_tests();
	datum_stratum_pending_job_quickdiff_tests();
	datum_stratum_quickdiff_job_tests();
	datum_stratum_quickdiff_job_index_tests();
	datum_stratum_unbound_quickdiff_tests();
	datum_stratum_vardiff_measure_tests();
	datum_stratum_share_credit_tests();
	datum_stratum_mod_username_tests();
	datum_stratum_minimum_difficulty_configure_tests();
	datum_stratum_string_request_id_tests();
	datum_blake2b_coinbase_selection_tests();
	datum_stratum_coinbaser_ready_tests();
	datum_stratum_new_thread_job_tests();
	datum_stratum_new_thread_empty_work_tests();
	datum_blake2b_h_not_zero_tests();
	datum_blake2b_client_pot_commitment_tests();
	datum_blake2b_unmasked_block_tests();
	datum_stratum_abw_block_request_tests();
	datum_blake2b_refresh_time_offset_tests();
	datum_block_coinbase_witness_tests();
}
