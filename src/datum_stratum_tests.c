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

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_pow.h"
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
	
	// Solo work commits to the template's own key whatever ABW says.
	job.is_datum_job = false;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
	datum_test(memcmp(c_local, c_pot, sizeof(c_local)) != 0);
	
	// Pooled work can also operate without ABW.
	tdata.abw_enabled = false;
	tdata.abw_assignment_id = 0;
	job.is_datum_job = true;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
}

// What a job at this pot commits to if it uses this key hash and clear_bits.
static void datum_blake2b_expected_commitment(unsigned char *expected, const T_DATUM_STRATUM_JOB *job,
	const T_DATUM_STRATUM_COINBASE *cb, unsigned char pot, uint32_t txcount, uint8_t clear_bits, const unsigned char *key_hash) {
	unsigned char cb_txn[128], merkle[32];
	const size_t cb_len = (size_t)cb->coinb1_len + 12 + (size_t)cb->coinb2_len;
	memcpy(cb_txn, cb->coinb1_bin, cb->coinb1_len);
	memset(cb_txn + cb->coinb1_len, 0, 12);
	memcpy(cb_txn + cb->coinb1_len + 12, cb->coinb2_bin, cb->coinb2_len);
	cb_txn[job->target_pot_index] = pot;
	double_sha256(merkle, cb_txn, cb_len);
	datum_test(datum_blake2b_header_commitment_from_key_hash(expected, job->block_template->version,
		job->block_template->previousblockhash_bin, (uint32_t)job->block_template->height, merkle,
		job->blake2b_time_on_wire, job->block_template->bits_uint, txcount, job->blake2b_flags,
		clear_bits, key_hash, (const unsigned char[32]){0}));
}

static void datum_stratum_test_coinbaser_locks(void);

static void datum_blake2b_solo_blind_tests(void) {
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_JOB_H1 h1;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[3];
	const unsigned char key[16] = {1,2,3};
	unsigned char got[32], want[32], raw[32] = {0}, masked[32];
	char id[32];
	
	datum_stratum_test_coinbaser_locks();
	tdata.version = 0x20000000;
	tdata.height = 200;
	tdata.bits_uint = 0x1d00ffff;
	tdata.generation = 9;
	memcpy(tdata.own_xor_key, key, 16);
	datum_test(datum_blake2b_xor_key_hash(tdata.own_xor_key_hash, key));
	job.block_template = &tdata;
	job.template_generation = 9;
	job.blake2b_time_on_wire = 1000;
	job.coinbase[0].coinb1_len = 20;
	job.coinbase[0].coinb2_len = 8;
	memset(job.coinbase[0].coinb1_bin, 0x11, 20);
	memset(job.coinbase[0].coinb2_bin, 0x22, 8);
	job.subsidy_only_coinbase = job.coinbase[0];
	job.subsidy_only_coinbase.coinb2_bin[0] ^= 0xaa;
	job.target_pot_index = 4;
	
	// Every kind of work commits to the key hash with clear_bits = 32 + pot.
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 0, got, NULL));
	datum_blake2b_expected_commitment(want, &job, &job.coinbase[0], 0, 1, 32, tdata.own_xor_key_hash);
	datum_test(!memcmp(got, want, 32));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 5, got, NULL));
	datum_blake2b_expected_commitment(want, &job, &job.coinbase[0], 5, 1, 37, tdata.own_xor_key_hash);
	datum_test(!memcmp(got, want, 32));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.subsidy_only_coinbase, true, 5, got, NULL));
	datum_blake2b_expected_commitment(want, &job, &job.subsidy_only_coinbase, 5, 1, 37, tdata.own_xor_key_hash);
	datum_test(!memcmp(got, want, 32));
	
	// A raw hash at the target is no block once masked, and is never read raw.
	memset(job.block_target, 0, sizeof(job.block_target));
	datum_test(!datum_stratum_share_is_unmasked_block(&job, raw));
	datum_test(!datum_stratum_own_key_share_is_block(&job, raw, 0, masked));
	datum_test(memcmp(masked, raw, 32) != 0);
	datum_test(!memcmp(masked + 28, raw + 28, 4)); // the top 32 bits stay clear
	memset(job.block_target, 0xff, sizeof(job.block_target));
	datum_test(datum_stratum_own_key_share_is_block(&job, raw, 0, masked));
	
	// The job id as notify sends it. Anything else is an unknown job.
	snprintf(job.job_id, sizeof(job.job_id), "%8.8x%2.2x%4.4x", 0x69052bd0U, 4U, (unsigned int)(3 ^ STRATUM_JOB_INDEX_XOR));
	global_cur_stratum_jobs[3] = &job;
	
	snprintf(id, sizeof(id), "%s00", job.job_id);
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!strcmp(h1.mode, "solo"));
	datum_test(h1.clear_bits == 37);
	datum_test(h1.txcount == 1);
	datum_test(h1.version == 0xa0000000);
	datum_test(!memcmp(h1.xor_key_hash, tdata.own_xor_key_hash, 32));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 5, got, NULL));
	datum_test(!memcmp(h1.h2, got, 32));
	
	snprintf(id, sizeof(id), "Q%s00", job.job_id);
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!memcmp(h1.h2, got, 32));
	
	snprintf(id, sizeof(id), "N%sff", job.job_id);
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.subsidy_only_coinbase, true, 5, got, NULL));
	datum_test(!memcmp(h1.h2, got, 32));
	
	snprintf(id, sizeof(id), "N%s00", job.job_id);
	datum_test(!datum_stratum_job_h1_for_id(id, 5, &h1));
	snprintf(id, sizeof(id), "%sff", job.job_id);
	datum_test(!datum_stratum_job_h1_for_id(id, 5, &h1));
	snprintf(id, sizeof(id), "%s06", job.job_id);
	datum_test(!datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!datum_stratum_job_h1_for_id("", 5, &h1));
	datum_test(!datum_stratum_job_h1_for_id("zzzzzzzzzzzzzzzz", 5, &h1));
	snprintf(id, sizeof(id), "%s00", job.job_id);
	id[9] ^= 1; // a digit stratum_get_job doesn't compare
	datum_test(!datum_stratum_job_h1_for_id(id, 5, &h1));
	
	// A reused template slot no longer describes the job.
	snprintf(id, sizeof(id), "%s00", job.job_id);
	tdata.generation = 10;
	datum_test(!datum_stratum_job_h1_for_id(id, 5, &h1));
	tdata.generation = 9;
	
	// Neither does a job whose coinbases are still being written, rebuilt from the job...
	job.need_coinbaser = true;
	datum_test(!datum_stratum_job_h1_for_id(id, 5, &h1));
	// ...but its empty (N) job is: its coinbase is made with the job, before any coinbaser, and goes out first
	// after a new block. A renter that can't open it ends the rental at every block change.
	{
		char nid[32];
		unsigned char n_h2[32];
		snprintf(nid, sizeof(nid), "N%sff", job.job_id);
		datum_test(datum_stratum_job_h1_for_id(nid, 5, &h1));
		datum_test(datum_stratum_job_blake2b_commitment(&job, &job.subsidy_only_coinbase, true, 5, n_h2, NULL));
		datum_test(!memcmp(h1.h2, n_h2, 32));
		datum_test(h1.txcount == 1);
	}
	// A full job that went out while the coinbaser was late (sent on coinbase[0] after its 5 s timeout) is
	// answered as it was sent, from the record notify keeps, and still after the coinbaser rewrites coinbase[0].
	{
		T_DATUM_JOB_H1 sent, got;
		unsigned char was[32];
		datum_test(datum_stratum_job_blake2b_commitment_h1(&job, &job.coinbase[0], false, 5, NULL, &sent));
		datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 5, was, NULL));
		datum_test(!memcmp(sent.h2, was, 32));
		datum_stratum_sent_h1_record(id, 5, &sent);
		datum_test(datum_stratum_job_h1_for_id(id, 5, &got));
		datum_test(!memcmp(got.h2, was, 32));
		job.coinbase[0].coinb2_bin[0] ^= 0x55; // the late coinbaser's rewrite
		datum_test(datum_stratum_job_h1_for_id(id, 5, &got));
		datum_test(!memcmp(got.h2, was, 32));
		// another pot of the same id was never sent: no record, and the job is still waiting
		datum_test(!datum_stratum_job_h1_for_id(id, 6, &got));
		job.coinbase[0].coinb2_bin[0] ^= 0x55;
		datum_test(!datum_stratum_sent_h1_find("never-sent", 5, &got));
		datum_stratum_sent_h1_clear();
		datum_test(!datum_stratum_sent_h1_find(id, 5, &got));
	}
	job.need_coinbaser = false;
	
	// Pool work says plainly which key it uses.
	job.is_datum_job = true;
	job.pool_key = true;
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!strcmp(h1.mode, "pool-key"));
	datum_test(h1.clear_bits == 37);
	datum_test(!memcmp(h1.xor_key_hash, tdata.own_xor_key_hash, 32));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 5, got, NULL));
	datum_test(!memcmp(h1.h2, got, 32));
	snprintf(id, sizeof(id), "N%sff", job.job_id);
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!strcmp(h1.mode, "pool-key"));
	datum_test(h1.clear_bits == 37);
	datum_test(h1.txcount == 1);
	snprintf(id, sizeof(id), "%s00", job.job_id);
	memset(job.block_target, 0xff, sizeof(job.block_target));
	datum_test(!datum_stratum_share_is_unmasked_block(&job, raw));
	datum_test(datum_stratum_own_key_share_is_block(&job, raw, 0, masked));
	memset(job.block_target, 0, sizeof(job.block_target));
	datum_test(!datum_stratum_own_key_share_is_block(&job, raw, 0, masked));
	job.pool_key = false;
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!strcmp(h1.mode, "pool-null"));
	datum_test(h1.clear_bits == 0);
	datum_test(datum_blake2b_xor_key_hash(want, (const unsigned char[16]){0}));
	datum_test(!memcmp(h1.xor_key_hash, want, 32));
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	memset(tdata.xor_key_hash, 0x5a, 32);
	datum_test(datum_stratum_job_h1_for_id(id, 5, &h1));
	datum_test(!strcmp(h1.mode, "abw"));
	datum_test(h1.clear_bits == 37);
	datum_test(!memcmp(h1.xor_key_hash, tdata.xor_key_hash, 32));
	
	global_cur_stratum_jobs[3] = saved_job;
}

static void datum_blake2b_unmasked_block_tests(void) {
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA block_template = {0};
	unsigned char hash[32] = {0};
	
	job.block_template = &block_template;
	memset(job.block_target, 0xff, sizeof(job.block_target));
	datum_test(!datum_stratum_share_is_unmasked_block(&job, hash));
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

void datum_stratum_tests(void) {
	datum_stratum_mod_username_tests();
	datum_stratum_minimum_difficulty_configure_tests();
	datum_stratum_string_request_id_tests();
	datum_blake2b_coinbase_selection_tests();
	datum_stratum_coinbaser_ready_tests();
	datum_stratum_new_thread_job_tests();
	datum_stratum_new_thread_empty_work_tests();
	datum_blake2b_h_not_zero_tests();
	datum_blake2b_client_pot_commitment_tests();
	datum_blake2b_solo_blind_tests();
	datum_blake2b_unmasked_block_tests();
	datum_stratum_abw_block_request_tests();
	datum_blake2b_refresh_time_offset_tests();
	datum_block_coinbase_witness_tests();
}
