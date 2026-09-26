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

#ifndef _DATUM_PROTOCOL_INTERNAL_H_
#define _DATUM_PROTOCOL_INTERNAL_H_

#include <stdatomic.h>

#include "datum_protocol.h"

typedef struct T_DATUM_REPLAY_PENDING T_DATUM_REPLAY_PENDING;

extern DATUM_ENC_PRECOMP session_precomp;
extern atomic_int datum_protocol_client_active;
extern unsigned char datum_state;
extern int server_out_buf;
extern unsigned char server_send_buffer[DATUM_PROTOCOL_BUFFER_SIZE];
extern uint32_t sending_header_key;
extern unsigned char session_nonce_sender[crypto_box_NONCEBYTES];
extern atomic_bool datum_protocol_bulk_enabled;
extern size_t datum_replay_count;
extern atomic_uint_fast64_t datum_session_generation;
extern unsigned char datum_protocol_next_job_idx;
extern T_DATUM_PROTOCOL_JOB datum_jobs[MAX_DATUM_PROTOCOL_JOBS];

// Scratch buffer for replies built on the protocol thread, and the most a
// 0x50 0x11 reply may hold before its terminator and padding.
#define DATUM_PROTOCOL_TEMP_DATA_SIZE (DATUM_PROTOCOL_MAX_CMD_DATA_SIZE + 16384)
#define DATUM_STXLIST_REPLY_MAX (DATUM_PROTOCOL_MAX_CMD_DATA_SIZE - 113)
extern unsigned char temp_data[DATUM_PROTOCOL_TEMP_DATA_SIZE];
bool datum_protocol_stxlist_reply_fits(size_t offset, size_t txn_size);
int datum_protocol_job_validation_stxlist_byid(int len, unsigned char *data);

uint32_t datum_header_xor_feedback(uint32_t i);
int datum_protocol_flush_socket(int sockfd);
void datum_protocol_bulk_reset(void);
int datum_protocol_bulk_cmd_for_session(
	const void *data, int len, uint64_t expected_session_generation);
int datum_protocol_bulk_cmd(const void *data, int len);
void datum_protocol_bulk_drain_one(void);
int datum_protocol_bulk_ack(int len, const unsigned char *data);

int datum_protocol_mining_cmd_for_session(
	void *data, int len, uint64_t expected_session_generation);
void datum_protocol_replay_clear(void);
T_DATUM_REPLAY_PENDING *datum_protocol_replay_add(
	const T_DATUM_PROTOCOL_POW *pow, const unsigned char *message,
	size_t message_size);
void datum_protocol_replay_mark_responded_legacy(
	uint32_t nonce, uint8_t target_pot, uint8_t job_id);

void datum_protocol_abw_reset(void);
bool datum_protocol_abw_assignment_revealed(uint8_t assignment_id);
bool datum_protocol_abw_cache_candidate(const T_DATUM_PROTOCOL_POW *pow,
	const unsigned char *full_cb_tx, size_t full_cb_tx_size,
	const unsigned char *raw_pow_hash);
int datum_protocol_abw_candidate_receipt(int len, unsigned char *data);
int datum_protocol_abw_candidate_release(int len, unsigned char *data);
int datum_protocol_abw_activation(int len, unsigned char *data);
int datum_protocol_abw_assignment_notice(int len, unsigned char *data);
int datum_protocol_abw_reveal(int len, unsigned char *data);

int datum_protocol_mining_cmd(void *data, int len);
int datum_protocol_client_configure(int len, unsigned char *data);
int datum_protocol_mining_cmd5(
	T_DATUM_PROTOCOL_HEADER *header, unsigned char *data);
int datum_protocol_share_response(int len, unsigned char *data);

#endif
