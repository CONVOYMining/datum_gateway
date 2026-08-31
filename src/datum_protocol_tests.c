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
#include "datum_pow.h"
#include "datum_protocol_internal.h"
#include "datum_utils.h"

static void datum_protocol_config_v3_tests(void) {
	global_config_t saved_config = datum_config;
	const unsigned char saved_state = datum_state;
	unsigned char payload[128] = {0};
	size_t i = 0;
	
	payload[i++] = 3;
	payload[i++] = 1;
	payload[i++] = 0x51;
	pk_u64le(payload, i, UINT64_C(0x887766555d965e4e)); i += 8;
	pk_u64le(payload, i, UINT64_C(0x887766555d965e4e));
	memset(payload + i + 8, 0x5a, 32);
	i += 40;
	payload[i++] = 3;
	memcpy(payload + i, "tag", 3); i += 3;
	pk_u64le(payload, i, 1024); i += 8;
	payload[i++] = 0;
	payload[i++] = 0xFE;
	datum_state = 3;
	datum_test(datum_protocol_client_configure((int)i, payload));
	datum_test(datum_config.prime_id == UINT64_C(0x887766555d965e4e));
	datum_test(datum_config.override_mining_pool_scriptsig_len == 1);
	datum_test(datum_config.override_mining_pool_scriptsig[0] == 0x51);
	datum_test(!strcmp(datum_config.override_mining_coinbase_tag_primary, "tag"));
	datum_test(datum_config.override_vardiff_min == 1024);
	payload[0] = 2;
	datum_test(!datum_protocol_client_configure((int)i, payload));
	datum_config = saved_config;
	datum_state = saved_state;
}

static void datum_protocol_resume_tests(void) {
	T_DATUM_PROTOCOL_POW pow = {0};
	const unsigned char message[] = {0x27, 0xFE};
	
	datum_protocol_replay_clear();
	pow.nonce = UINT64_C(0x100000009);
	pow.target_byte = 10;
	pow.datum_job_id = 3;
	datum_test(datum_protocol_replay_add(&pow, message, sizeof(message)) != NULL);
	datum_test(datum_replay_count == 1);
	datum_protocol_replay_mark_responded_legacy(8, 10, 3);
	datum_test(datum_replay_count == 1);
	datum_protocol_replay_mark_responded_legacy(9, 10, 3);
	datum_test(datum_replay_count == 0);
	
	datum_test(datum_protocol_replay_add(&pow, message, sizeof(message)) != NULL);
	pow.nonce = UINT64_C(0x200000009);
	datum_test(datum_protocol_replay_add(&pow, message, sizeof(message)) != NULL);
	datum_protocol_replay_mark_responded_legacy(9, 10, 3);
	datum_test(datum_replay_count == 2);
	datum_protocol_replay_clear();
	
	unsigned char backpressure_message[32] = {0x27, 0xFE};
	unsigned char backpressure_before[sizeof(backpressure_message)];
	unsigned char nonce_before[sizeof(session_nonce_sender)];
	memcpy(backpressure_before, backpressure_message,
		sizeof(backpressure_message));
	memcpy(nonce_before, session_nonce_sender, sizeof(nonce_before));
	const uint32_t header_key_before = sending_header_key;
	const int buffered_before = server_out_buf;
	server_out_buf = DATUM_PROTOCOL_BUFFER_SIZE - 1;
	datum_test(datum_protocol_mining_cmd(backpressure_message, 2) == -1);
	datum_test(sending_header_key == header_key_before);
	datum_test(!memcmp(session_nonce_sender, nonce_before, sizeof(nonce_before)));
	datum_test(!memcmp(backpressure_message, backpressure_before,
		sizeof(backpressure_message)));
	datum_test(server_out_buf == DATUM_PROTOCOL_BUFFER_SIZE - 1);
	server_out_buf = buffered_before;
}

static void datum_protocol_migration_tests(void) {
	global_config_t saved_config = datum_config;
	unsigned char payload[192] = {0};
	unsigned char command[193] = {0xA4};
	unsigned char home_payload[192] = {0};
	T_DATUM_PROTOCOL_HEADER header = {0};
	char endpoint[sizeof(datum_config.datum_pool_host)];
	char endpoint_pubkey[sizeof(datum_config.datum_pool_pubkey)];
	char configured_pubkey[129];
	char migrated_pubkey[129];
	const char host[] = "next.pool.example";
	const unsigned char return_home[] = {0, 1, 0xFE};
	int port;
	size_t i = 0;
	size_t key_offset;
	size_t home_i = 0;
	
	for (size_t j = 0; j < 32; ++j) {
		uchar_to_hex(configured_pubkey + j * 2, j);
		uchar_to_hex(configured_pubkey + 64 + j * 2, 32 + j);
	}
	configured_pubkey[128] = '\0';
	strcpy(datum_config.datum_pool_host, "configured.pool.example");
	datum_config.datum_pool_port = 28915;
	strcpy(datum_config.datum_pool_pubkey, configured_pubkey);
	datum_config.datum_pool_migration_host[0] = '\0';
	datum_config.datum_pool_migration_port = 0;
	datum_config.datum_pool_migration_pubkey[0] = '\0';
	datum_config.datum_pool_migration_deadline_ms = 0;
	datum_config.datum_pool_migration_max_seconds = 86400;
	
	payload[i++] = 0; // revision
	payload[i++] = 0; // migrate
	pk_u16le(payload, i, sizeof(host) - 1); i += 2;
	memcpy(payload + i, host, sizeof(host) - 1); i += sizeof(host) - 1;
	pk_u16le(payload, i, 29634); i += 2;
	key_offset = i;
	for (size_t j = 0; j < 64; ++j) payload[i++] = j;
	payload[i++] = 0xFE;
	memcpy(command + 1, payload, i);
	header.cmd_len = i + 1;
	
	datum_test(datum_protocol_mining_cmd5(&header, command) == 0);
	datum_test(!datum_config.datum_pool_migration_host[0]);
	header.is_signed = true;
	datum_test(datum_protocol_mining_cmd5(&header, command) == -1);
	datum_test(!strcmp(datum_config.datum_pool_host, "configured.pool.example"));
	datum_test(datum_config.datum_pool_port == 28915);
	datum_test(!strcmp(datum_config.datum_pool_migration_host, host));
	datum_test(datum_config.datum_pool_migration_port == 29634);
	datum_test(!strcmp(datum_config.datum_pool_migration_pubkey, configured_pubkey));
	datum_test(datum_config.datum_pool_migration_deadline_ms > current_time_millis());
	
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, host));
	datum_test(port == 29634);
	datum_test(!strcmp(endpoint_pubkey, configured_pubkey));
	datum_test(!datum_config.datum_pool_migration_host[0]);
	datum_test(datum_config.datum_pool_migration_port == 0);
	datum_test(!datum_config.datum_pool_migration_pubkey[0]);
	datum_test(datum_config.datum_pool_migration_deadline_ms == 0);
	datum_test(!datum_protocol_migration_expired(current_time_millis()));
	
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, "configured.pool.example"));
	datum_test(port == 28915);
	datum_test(!strcmp(endpoint_pubkey, configured_pubkey));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	datum_test(datum_protocol_migration_request(
		(int)sizeof(return_home), return_home) == 1);
	
	for (size_t j = 0; j < 64; ++j) {
		payload[key_offset + j] = 0x80 + j;
		uchar_to_hex(migrated_pubkey + j * 2, 0x80 + j);
	}
	migrated_pubkey[128] = '\0';
	datum_test(datum_protocol_migration_request((int)i, payload) == -1);
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint_pubkey, migrated_pubkey));
	datum_config.datum_pool_migration_max_seconds = 0;
	datum_test(datum_protocol_migration_request(
		(int)sizeof(return_home), return_home) == 1);
	datum_test(datum_protocol_migration_expired(UINT64_MAX));
	datum_config.datum_pool_migration_max_seconds = 86400;
	datum_test(datum_protocol_migration_request(
		(int)sizeof(return_home), return_home) == -1);
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, datum_config.datum_pool_host));
	datum_test(port == datum_config.datum_pool_port);
	datum_test(!strcmp(endpoint_pubkey, datum_config.datum_pool_pubkey));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	
	datum_config.datum_pool_migration_max_seconds = 0;
	datum_test(datum_protocol_migration_request((int)i, payload) == 1);
	datum_test(!datum_config.datum_pool_migration_host[0]);
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, datum_config.datum_pool_host));
	datum_test(port == datum_config.datum_pool_port);
	datum_test(!strcmp(endpoint_pubkey, datum_config.datum_pool_pubkey));
	datum_config.datum_pool_migration_max_seconds = 86400;
	
	datum_test(datum_protocol_migration_request((int)i, payload) == -1);
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	
	home_payload[home_i++] = 0; // revision
	home_payload[home_i++] = 0; // migrate
	pk_u16le(home_payload, home_i, strlen(datum_config.datum_pool_host)); home_i += 2;
	memcpy(home_payload + home_i, datum_config.datum_pool_host,
		strlen(datum_config.datum_pool_host));
	home_i += strlen(datum_config.datum_pool_host);
	pk_u16le(home_payload, home_i, datum_config.datum_pool_port); home_i += 2;
	for (size_t j = 0; j < 64; ++j) home_payload[home_i++] = j;
	home_payload[home_i++] = 0xFE;
	datum_test(datum_protocol_migration_request((int)home_i, home_payload) == -1);
	datum_test(datum_config.datum_pool_migration_deadline_ms == 0);
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!strcmp(endpoint, datum_config.datum_pool_host));
	datum_test(port == datum_config.datum_pool_port);
	datum_test(!strcmp(endpoint_pubkey, datum_config.datum_pool_pubkey));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	datum_test(datum_protocol_migration_request((int)home_i, home_payload) == 1);
	
	datum_config.datum_pool_migration_host[0] = 'x';
	datum_config.datum_pool_migration_host[1] = '\0';
	datum_config.datum_pool_migration_port = 1;
	strcpy(datum_config.datum_pool_migration_pubkey, configured_pubkey);
	datum_config.datum_pool_migration_deadline_ms = current_time_millis() - 1;
	datum_test(datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(datum_protocol_migration_expired(current_time_millis()));
	datum_test(datum_protocol_migration_request((int)i, payload) == -1);
	datum_test(!datum_config.datum_pool_migration_host[0]);
	datum_test(!datum_protocol_take_connect_endpoint(
		endpoint, sizeof(endpoint), &port,
		endpoint_pubkey, sizeof(endpoint_pubkey)));
	datum_test(!datum_protocol_migration_expired(UINT64_MAX));
	
	payload[0] = 1;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	payload[0] = 0;
	payload[1] = 2;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	payload[1] = 0;
	payload[i - 1] = 0;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	pk_u16le(payload, 4 + sizeof(host) - 1, 0);
	payload[i - 1] = 0xFE;
	datum_test(datum_protocol_migration_request((int)i, payload) == 0);
	
	datum_config = saved_config;
}

static void datum_pow_response_large_difficulty_test(void) {
	unsigned char accepted[9] = {DATUM_POW_SHARE_RESPONSE_ACCEPTED};
	unsigned char rejected[9] = {DATUM_POW_SHARE_RESPONSE_REJECTED};
	const uint64_t saved_accepted_count = datum_accepted_share_count;
	const uint64_t saved_accepted_diff = datum_accepted_share_diff;
	const uint64_t saved_rejected_count = datum_rejected_share_count;
	const uint64_t saved_rejected_diff = datum_rejected_share_diff;
	
	accepted[7] = 40;
	rejected[7] = 40;
	datum_accepted_share_count = 0;
	datum_accepted_share_diff = 0;
	datum_rejected_share_count = 0;
	datum_rejected_share_diff = 0;
	datum_test(datum_protocol_share_response(sizeof(accepted), accepted));
	datum_test(datum_protocol_share_response(sizeof(rejected), rejected));
	datum_test(datum_accepted_share_count == 1);
	datum_test(datum_accepted_share_diff == (1ULL << 40));
	datum_test(datum_rejected_share_count == 1);
	datum_test(datum_rejected_share_diff == (1ULL << 40));
	accepted[7] = 63;
	datum_test(datum_protocol_share_response(sizeof(accepted), accepted));
	datum_test(datum_accepted_share_diff == (1ULL << 63) + (1ULL << 40));
	accepted[7] = 64;
	datum_test(datum_protocol_share_response(sizeof(accepted), accepted));
	datum_test(datum_accepted_share_diff == UINT64_MAX);
	rejected[7] = 64;
	datum_test(datum_protocol_share_response(sizeof(rejected), rejected));
	datum_test(datum_rejected_share_diff == UINT64_MAX);
	
	datum_accepted_share_count = saved_accepted_count;
	datum_accepted_share_diff = saved_accepted_diff;
	datum_rejected_share_count = saved_rejected_count;
	datum_rejected_share_diff = saved_rejected_diff;
}

static void datum_pow_recycled_protocol_job_test(void) {
	T_DATUM_STRATUM_JOB * const jobs = calloc(MAX_DATUM_PROTOCOL_JOBS + 1, sizeof(*jobs));
	T_DATUM_TEMPLATE_DATA * const templates = calloc(MAX_DATUM_PROTOCOL_JOBS + 1, sizeof(*templates));
	unsigned char msg[2048];
	T_DATUM_PROTOCOL_POW pow = {0};
	const bool saved_pass_full_users = datum_config.datum_pool_pass_full_users;
	const bool saved_pass_workers = datum_config.datum_pool_pass_workers;
	char saved_pool_address[sizeof(datum_config.mining_pool_address)];
	
	if (!jobs || !templates) {
		datum_test(jobs && templates);
		free(templates);
		free(jobs);
		return;
	}
	memcpy(saved_pool_address, datum_config.mining_pool_address, sizeof(saved_pool_address));
	datum_config.datum_pool_pass_full_users = false;
	datum_config.datum_pool_pass_workers = false;
	strcpy(datum_config.mining_pool_address, "pool");
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	
	for(size_t i=0;i<MAX_DATUM_PROTOCOL_JOBS + 1;i++) {
		T_DATUM_STRATUM_JOB * const job = &jobs[i];
		job->block_template = &templates[i];
		job->height = 100 + i;
		job->coinbase_value = 5000000000ULL + i;
		job->target_pot_index = 4;
		job->datum_coinbaser_id = (unsigned char)i;
		job->prevhash_bin[0] = (unsigned char)(0xa0 + i);
		job->nbits_bin[0] = (unsigned char)(0xb0 + i);
		job->coinbase[2].coinb1_len = 1;
		job->coinbase[2].coinb2_len = 1;
		job->coinbase[2].coinb1_bin[0] = (unsigned char)(0xc0 + i);
		job->coinbase[2].coinb2_bin[0] = (unsigned char)(0xd0 + i);
		job->subsidy_only_coinbase.coinb1_len = 1;
		job->subsidy_only_coinbase.coinb2_len = 1;
		job->subsidy_only_coinbase.coinb1_bin[0] = (unsigned char)(0xe0 + i);
		job->subsidy_only_coinbase.coinb2_bin[0] = (unsigned char)(0xf0 + i);
		snprintf(job->job_id, sizeof(job->job_id), "job-%02zu", i);
	}
	
	pow.datum_job_id = datum_protocol_setup_new_job_idx(&jobs[0]);
	pow.sjob = &jobs[0];
	memcpy(pow.stratum_job_id, jobs[0].job_id, sizeof(pow.stratum_job_id));
	pow.coinbase_id = 2;
	pow.blake2b_use_time_offset = true;
	pow.ntime = UINT64_C(0x1817161514131211);
	pow.nonce = UINT64_C(0x0807060504030201);
	pow.time_on_wire = UINT32_C(0x6553412f);
	pow.version = UINT32_C(0x20000000);
	pow.target_byte_index = jobs[0].target_pot_index;
	pow.target_byte = 1;
	
	// First use registers job 0 and its coinbase in remote slot 0.
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
	datum_test((msg[3] & 0x08) != 0);
	datum_test(upk_u32le(msg, 13) == pow.version);
	datum_test((msg[35] & DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET) != 0);
	datum_test(msg[39] == 0x03 && msg[40] == DATUM_POW_BLAKE2B);
	datum_test(upk_u64le(msg, 41) == pow.ntime);
	datum_test(upk_u64le(msg, 49) == pow.nonce);
	datum_test(msg[57] == 0x04 && upk_u32le(msg, 58) == pow.time_on_wire);
	datum_test(msg[62] == 0x01 && msg[63] == 0xa0);
	datum_test(msg[131] == 0x02 && msg[137] == 0xc0 && msg[138] == 0xd0);
	datum_test(datum_jobs[0].server_sjob == &jobs[0]);
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) > 0);
	datum_test((msg[35] & DATUM_POW_RESERVED_BLAKE2B_USE_TIME_OFFSET) != 0);
	pow.blake2b_use_time_offset = false;
	
	// Malformed local state must not index beyond the six generated variants.
	pow.coinbase_id = MAX_COINBASE_TYPES;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 0);
	pow.coinbase_id = 2;
	pow.subsidy_only = true;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 0);
	pow.coinbase_id = DATUM_COINBASE_ID_EMPTY;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 71);
	datum_test((msg[3] & 0x02) != 0);
	datum_test(msg[62] == 0x02 && msg[63] == DATUM_COINBASE_ID_EMPTY);
	datum_test(msg[68] == 0xe0 && msg[69] == 0xf0);
	datum_test(datum_jobs[0].server_has_coinbase_empty);
	pow.subsidy_only = false;
	pow.coinbase_id = 2;
	
	// snprintf returns the untruncated length. Ensure a long address+worker is
	// capped to the actual bytes in the protocol username field.
	datum_config.datum_pool_pass_workers = true;
	memset(datum_config.mining_pool_address, 'a', sizeof(datum_config.mining_pool_address) - 1);
	datum_config.mining_pool_address[sizeof(datum_config.mining_pool_address) - 1] = 0;
	memset(pow.username, 'b', sizeof(pow.username) - 1);
	pow.username[sizeof(pow.username) - 1] = 0;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 443);
	datum_test(msg[414] == 0 && msg[442] == 0xFE);
	datum_config.datum_pool_pass_workers = false;
	strcpy(datum_config.mining_pool_address, "pool");
	pow.username[0] = 0;
	
	// Cycle the eight protocol IDs. Assigning job 8 reuses slot 0 and wipes
	// the remote cache so the next share must re-upload merkle and coinbase.
	for(size_t i=1;i<MAX_DATUM_PROTOCOL_JOBS + 1;i++) {
		jobs[i].datum_job_idx = datum_protocol_setup_new_job_idx(&jobs[i]);
	}
	datum_test(jobs[MAX_DATUM_PROTOCOL_JOBS].datum_job_idx == 0);
	datum_test(datum_jobs[0].sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);
	datum_test(datum_jobs[0].server_sjob == NULL);
	
	pow.sjob = &jobs[MAX_DATUM_PROTOCOL_JOBS];
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	pow.target_byte_index = pow.sjob->target_pot_index;
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
	datum_test(msg[62] == 0x01 && msg[63] == 0xa8);
	datum_test(msg[131] == 0x02 && msg[137] == 0xc8 && msg[138] == 0xd8);
	datum_test(datum_jobs[0].server_sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);
	
	// A delayed share for the old job must switch the remote cache back to its
	// exact context; a following new-job share must switch it forward again.
	pow.sjob = &jobs[0];
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
	datum_test(msg[63] == 0xa0 && msg[137] == 0xc0 && msg[138] == 0xd0);
	datum_test(datum_jobs[0].server_sjob == &jobs[0]);
	pow.sjob = &jobs[MAX_DATUM_PROTOCOL_JOBS];
	memcpy(pow.stratum_job_id, pow.sjob->job_id, sizeof(pow.stratum_job_id));
	datum_test(datum_protocol_pow_build_message(&pow, msg, sizeof(msg)) == 140);
	datum_test(msg[63] == 0xa8 && msg[137] == 0xc8 && msg[138] == 0xd8);
	datum_test(datum_jobs[0].server_sjob == &jobs[MAX_DATUM_PROTOCOL_JOBS]);
	
	memset(datum_jobs, 0, sizeof(datum_jobs));
	datum_protocol_next_job_idx = 0;
	memcpy(datum_config.mining_pool_address, saved_pool_address, sizeof(saved_pool_address));
	datum_config.datum_pool_pass_full_users = saved_pass_full_users;
	datum_config.datum_pool_pass_workers = saved_pass_workers;
	free(templates);
	free(jobs);
}

void datum_protocol_tests(void) {
	datum_protocol_config_v3_tests();
	datum_protocol_migration_tests();
	datum_protocol_resume_tests();
	datum_pow_response_large_difficulty_test();
	datum_pow_recycled_protocol_job_test();
}
