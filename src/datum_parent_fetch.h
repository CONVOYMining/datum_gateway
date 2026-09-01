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
 * Copyright (c) 2026 Luke Dashjr
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

#ifndef _DATUM_PARENT_FETCH_H_
#define _DATUM_PARENT_FETCH_H_

#include <stddef.h>
#include <stdint.h>

#define DATUM_PARENT_FETCH_STATUS_QUEUED 0x00
#define DATUM_PARENT_FETCH_STATUS_SUCCESS 0x01
#define DATUM_PARENT_FETCH_STATUS_JOB_MISMATCH 0xF0
#define DATUM_PARENT_FETCH_STATUS_BUSY 0xF6
#define DATUM_PARENT_FETCH_STATUS_UNAVAILABLE 0xF7
#define DATUM_PARENT_FETCH_STATUS_RPC_FAILED 0xF8

typedef void (*datum_parent_fetch_reply_fn)(
	uint8_t job_id, uint64_t session_generation, uint8_t status,
	const uint8_t parent_hash[32],
	const uint8_t *block, size_t block_size);

int datum_parent_fetch_init(datum_parent_fetch_reply_fn reply);
uint8_t datum_parent_fetch_enqueue(
	uint8_t job_id, uint64_t session_generation,
	const uint8_t parent_hash[32]);

#endif
