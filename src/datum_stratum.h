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
 * Copyright (c) 2024-2026 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors
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

#ifndef _DATUM_STRATUM_H_
#define _DATUM_STRATUM_H_

#include <stdbool.h>
#include <stdint.h>

#ifndef T_DATUM_CLIENT_DATA
	#include "datum_sockets.h"
#endif

#ifndef T_DATUM_TEMPLATE_DATA
	#include "datum_blocktemplates.h"
#endif

#define MAX_STRATUM_JOBS 256

#define MAX_COINBASE_TYPES 6
#define DATUM_COINBASE_ID_EMPTY 0xff
#define COINBASE_TYPE_TINY 0 // "empty", just pays pool
#define COINBASE_TYPE_SMALL 1 // Nicehash needs a tiny coinb1, among other things. Max 500 bytes.
#define COINBASE_TYPE_ANTMAIN 2 // Hack for antminer stock firmware to 750 bytes
#define COINBASE_TYPE_RESPECTABLE 3 // 6500 byte max (whatsminers)
#define COINBASE_TYPE_YUGE 4 // 16KB max (ePIC, bitaxe)
#define COINBASE_TYPE_ANTMAIN2 5 // 2.25KB max (S21, +?)

// Submitblock json rpc command max size is max block size * 2 for ascii plus some breathing room
#define MAX_SUBMITBLOCK_SIZE 8500000

/////////////////////////////////
// Stratum job types
/////////////////////////////////

// Potential job paths are:
// 1 -> 3 -> 4 -> 5 -> 5 ...
// 2E -> 2F -> 4 -> 5 -> 5 ...

// Unknown job state. don't use this job.
#define JOB_STATE_UNKNOWN 0

// This job is empty only. No template data available to switch to.
// No template is expected to end up on this job and we should IMMEDIATELY change to the next job when seen
#define JOB_STATE_EMPTY_ONLY 1

// this job is the result of a GBT call that got us the latest full template, but we need to do an empty first
// use for the empty.  wait for other threads.  immediately send the full work with the "blank" coinbase
// template is max sized for a "blank" coinbase.  other coinbases are not expected to be used
// this is the fastest empty->full work setup
#define JOB_STATE_EMPTY_PLUS 2

// this job is a full GBT wo/coinbaser which we're expected to immediately broadcast to miners after a JOB_STATE_EMPTY_ONLY
#define JOB_STATE_FULL_PRIORITY 3

// this is a normal job that waits for a full coinbaser setup after either JOB_STATE_FULL_PRIORITY or JOB_STATE_EMPTY_PLUS's full template
// it's broadcast immediately when ready
#define JOB_STATE_FULL_PRIORITY_WAIT_COINBASER 4

//
// all of the above jobs will use a GBT with the least common denominator for a block size/coinbaser combo.  coinbaser gets truncated.
//

// this is a normal job
// a GBT call is made, and the coinbaser is queued
// once the coinbaser returns (or fails) this job is gently broadcasted to all miners across the work change interval
// TODO: Fit the multiple coinbasers to multiple templates sized specifically for them
#define JOB_STATE_FULL_NORMAL_WAIT_COINBASER 5

////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////

typedef struct {
	char coinb1[STRATUM_COINBASE1_MAX_LEN];
	char coinb2[STRATUM_COINBASE2_MAX_LEN];
	unsigned char coinb1_bin[STRATUM_COINBASE1_MAX_LEN>>1];
	unsigned char coinb2_bin[STRATUM_COINBASE2_MAX_LEN>>1];
	
	int coinb1_len;
	int coinb2_len;
} T_DATUM_STRATUM_COINBASE;

typedef struct {
	unsigned char output_script[64];
	int output_script_len;
	uint64_t value_sats;
	int sigops;
} T_DATUM_TXN_OUTPUT;

typedef struct T_DATUM_STRATUM_JOB {
	int global_index;
	
	char job_id[24];
	char prevhash[68];
	unsigned char prevhash_bin[32];
	char version[10];
	uint32_t version_uint;
	char nbits[10];
	unsigned char nbits_bin[4];
	uint32_t nbits_uint;
	char ntime[18];
	unsigned char block_target[32];
	// BLAKE2b job fields
	uint32_t blake2b_time_on_wire;
	uint8_t blake2b_flags;
	// Tagged hash shared by every submitted share for this job.
	unsigned char blake2b_prevblock_hidden[32];
	
	T_DATUM_TEMPLATE_DATA *block_template;
	
	unsigned char merklebranch_count;
	char merklebranches_hex[24][72];
	unsigned char merklebranches_bin[24][32];
	
	char merklebranches_full[4096];
	
	// when fetching the coinbaser, we'll just stash all of the possible and valid output scripts here
	T_DATUM_TXN_OUTPUT available_coinbase_outputs[512];
	int available_coinbase_outputs_count;
	uint8_t pool_addr_script[MAX_OUTPUT_SCRIPT_LEN];
	uint8_t pool_addr_script_len;
	
	// multiple coinbase options
	// 0 = "empty" --- just pays pool addr, and possibly TIDES data.  extranonce in coinbase if fits, or in first output if not.
	// 1 = "nicehash" --- roughly 500 bytes total... smaller than antminer... has nothing before the extranonce OP_RETURN (or no extranonce OP_RETURN if enough space in the coinbase)
	// 2 = "antminer" --- roughly 730 bytes max size, using a larger coinb1 and UART sync bits.  This also works as a good default.
	// 3 = "whatsminer" --- max 6500 bytes tested.  does not need the extranonce OP_RETURN unless there's no space in the coinbase itself after tags
	// 4 = "huge" --- max 16kB --- this is probably the most we should reasonably attempt to do in the coinbase... something like 380 to 530 outputs, depending on the type of output
	// 5 = "antminer2" --- max 2250 bytes --- latest S21s appear to support this
	T_DATUM_STRATUM_COINBASE coinbase[MAX_COINBASE_TYPES];
	T_DATUM_STRATUM_COINBASE subsidy_only_coinbase;
	int target_pot_index; // where in coinb1 do we put our per-user vardiff pot value?
	
	uint64_t coinbase_value;
	uint64_t height;
	uint16_t enprefix;
	
	uint64_t tsms; // local timestamp for when job was created. can differ from the bitcoin network timestamp.
	
	bool is_new_block;
	bool is_stale_prevblock;
	
	int job_state;
	
	bool need_coinbaser;
	
	bool is_datum_job;
	unsigned char datum_job_idx;
	unsigned char datum_coinbaser_id;
} T_DATUM_STRATUM_JOB;

typedef struct T_DATUM_STRATUM_THREADPOOL_DATA {
	T_DATUM_STRATUM_JOB *cur_stratum_job;
	int latest_stratum_job_index;
	bool new_job;
	bool last_was_empty;
	int last_sent_job_state;
	uint64_t loop_tsms;
	bool full_coinbase_ready;
	
	int notify_remaining_count;
	uint64_t notify_start_time;
	uint64_t notify_last_time;
	uint64_t notify_delay_per_slot_tsms;
	int notify_last_cid;
	uint64_t last_job_height;
	uint64_t next_kick_check_tsms;
	
	char submitblock_req[MAX_SUBMITBLOCK_SIZE];
	
	void *dupes;
} T_DATUM_STRATUM_THREADPOOL_DATA;

typedef struct {
	unsigned char active_index; // the one we're adding to.  use the other for stats
	
	uint64_t last_swap_tsms; // timestamp of last swap
	uint64_t last_swap_ms; // length of time for the last
	
	uint64_t diff_accepted[2];
	
	uint64_t last_share_tsms;
} T_DATUM_STRATUM_USER_STATS;

typedef struct {
	uint32_t sid, sid_inv;
	uint64_t unique_id;
	uint64_t connect_tsms;
	char request_id_json[129];
	char useragent[128];
	char last_auth_username[192];
	
	bool extension_minimum_difficulty;
	double extension_minimum_difficulty_value;
	
	bool authorized;
	bool subscribed;
	uint64_t subscribe_tsms;
	
	uint64_t last_sent_diff;
	uint64_t current_diff;
	
	uint8_t stratum_job_targets[MAX_STRATUM_JOBS][32];
	uint64_t stratum_job_diffs[MAX_STRATUM_JOBS];
	
	unsigned char coinbase_selection;
	
	uint64_t share_diff_accepted;
	uint64_t share_count_accepted;
	
	uint64_t share_diff_rejected;
	uint64_t share_count_rejected;
	
	// for vardiff
	uint64_t share_count_since_snap;
	uint64_t share_diff_since_snap;
	uint64_t share_snap_tsms;
	
	bool quickdiff_active;
	uint64_t quickdiff_value;
	uint8_t quickdiff_target[32];
	
	uint64_t forced_high_min_diff;
	
	int last_sent_stratum_job_index;
	
	T_DATUM_STRATUM_USER_STATS stats;
	
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata;
} T_DATUM_MINER_DATA;

extern int global_latest_stratum_job_index;
extern pthread_rwlock_t stratum_global_job_ptr_lock;
extern T_DATUM_STRATUM_JOB *global_cur_stratum_jobs[MAX_STRATUM_JOBS];

const char *datum_stratum_mod_username(const char *username_s, char *username_buf, size_t username_buf_sz, uint16_t share_rnd, const char *modname, size_t modname_len);

int send_mining_notify(T_DATUM_CLIENT_DATA *c, bool clean, bool quickdiff, bool new_block);
void update_stratum_job(T_DATUM_TEMPLATE_DATA *block_template, bool new_block, int job_state);
void datum_stratum_job_refresh_blake2b(T_DATUM_STRATUM_JOB *s);
bool datum_stratum_job_blake2b_commitment_from_txn(const T_DATUM_STRATUM_JOB *s, const unsigned char *cb_txn, size_t cb_len, unsigned char target_pot, bool subsidy_only, unsigned char *commitment);
bool datum_stratum_job_blake2b_commitment(T_DATUM_STRATUM_JOB *s, const T_DATUM_STRATUM_COINBASE *cb, bool subsidy_only, unsigned char pot, unsigned char *commitment, unsigned char *coinb1);
bool datum_stratum_share_is_unmasked_block(
	const T_DATUM_STRATUM_JOB *job, const unsigned char *share_hash);
unsigned int datum_stratum_coinbase_index(const T_DATUM_STRATUM_THREADPOOL_DATA *sdata, const T_DATUM_MINER_DATA *miner, bool new_block);
void stratum_job_merkle_root_calc(T_DATUM_STRATUM_JOB *s, unsigned char *coinbase_txn_hash, unsigned char *merkle_root_output);
int assembleBlockAndSubmit(uint8_t *block_header, uint8_t *coinbase_txn, size_t coinbase_txn_size, T_DATUM_STRATUM_JOB *job, T_DATUM_STRATUM_THREADPOOL_DATA *sdata, const char *block_hash_hex, bool empty_work, const unsigned char *extranonce);
size_t datum_stratum_coinbase_for_block_hex(char *out, size_t out_size, const uint8_t *coinbase_txn, size_t coinbase_txn_size, bool add_witness);
bool datum_stratum_block_needs_witness(const T_DATUM_STRATUM_JOB *job, bool subsidy_only);
size_t datum_stratum_build_block_request_parts(char *out, size_t out_size,
	const uint8_t *block_header,
	const uint8_t *coinbase_txn, size_t coinbase_txn_size, bool add_witness,
	uint32_t transaction_count, const char *transactions_hex,
	size_t transactions_hex_size, bool subsidy_only, size_t *header_hex_offset);
bool datum_stratum_abw_finalize_block_request(char *request, size_t request_size,
	size_t header_hex_offset, const uint8_t raw_pow_hash[32],
	uint8_t xor_clear_bits, const uint8_t xor_key[16],
	const uint8_t expected_pow_hash[32], char block_hash_hex[65]);
void generate_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool empty_only);
int send_mining_set_difficulty(T_DATUM_CLIENT_DATA *c);
bool stratum_latest_empty_check_ready_for_full(void);

// Server thread main loop
void *datum_stratum_v1_socket_server(void *arg);
// DATUM socket callbacks
void datum_stratum_v1_socket_thread_init(T_DATUM_THREAD_DATA *my);
void datum_stratum_v1_socket_thread_loop(T_DATUM_THREAD_DATA *my);
int datum_stratum_v1_socket_thread_client_cmd(T_DATUM_CLIENT_DATA *c, char *line);
void datum_stratum_v1_socket_thread_client_closed(T_DATUM_CLIENT_DATA *c, const char *msg);
void datum_stratum_v1_socket_thread_client_new(T_DATUM_CLIENT_DATA *c);
int datum_stratum_v1_global_subscriber_count(void);
double datum_stratum_v1_est_total_th_sec(void);
void datum_stratum_v1_shutdown_all(void);

extern T_DATUM_SOCKET_APP *global_stratum_app;

extern pthread_rwlock_t need_coinbaser_rwlocks[MAX_STRATUM_JOBS];
extern bool need_coinbaser_rwlocks_init_done;

// Gateway-local share totals from connected stratum miners (not pool responses)
extern uint64_t stratum_client_accepted_share_count;
extern uint64_t stratum_client_accepted_share_diff;
extern uint64_t stratum_client_rejected_share_count;
extern uint64_t stratum_client_rejected_share_diff;

#endif
