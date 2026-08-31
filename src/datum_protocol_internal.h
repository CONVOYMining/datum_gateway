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

#include "datum_protocol.h"

typedef struct T_DATUM_REPLAY_PENDING T_DATUM_REPLAY_PENDING;

extern unsigned char datum_state;
extern int server_out_buf;
extern uint32_t sending_header_key;
extern unsigned char session_nonce_sender[crypto_box_NONCEBYTES];
extern size_t datum_replay_count;
extern unsigned char datum_protocol_next_job_idx;
extern T_DATUM_PROTOCOL_JOB datum_jobs[MAX_DATUM_PROTOCOL_JOBS];

void datum_protocol_replay_clear(void);
T_DATUM_REPLAY_PENDING *datum_protocol_replay_add(
	const T_DATUM_PROTOCOL_POW *pow, const unsigned char *message,
	size_t message_size);
void datum_protocol_replay_mark_responded_legacy(
	uint32_t nonce, uint8_t target_pot, uint8_t job_id);

int datum_protocol_mining_cmd(void *data, int len);
int datum_protocol_client_configure(int len, unsigned char *data);
int datum_protocol_mining_cmd5(
	T_DATUM_PROTOCOL_HEADER *header, unsigned char *data);
int datum_protocol_share_response(int len, unsigned char *data);

#endif
