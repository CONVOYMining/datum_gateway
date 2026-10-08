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

#ifndef _DATUM_STRATUM_DUPES_H_
#define _DATUM_STRATUM_DUPES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct T_DATUM_STRATUM_DUPE_ITEM {
	// things to compare against, in order, to check our list
	// in most cases, we shouldn't get beyond nonce, but we need the rest for completeness
	uint64_t job_tsms;
	uint8_t share_hash[28];
	
	struct T_DATUM_STRATUM_DUPE_ITEM *next;
} T_DATUM_STRATUM_DUPE_ITEM;

typedef struct T_DATUM_STRATUM_DUPES {
	// low 16 bits of nonce = index
	T_DATUM_STRATUM_DUPE_ITEM *index[65536];
	
	// memory - we target 8 shares per minute per connection.
	// suggested items: datum_expected_n_global_nonstale_shares(&datum_config)
	T_DATUM_STRATUM_DUPE_ITEM *ptr;
	size_t max_items;
	size_t current_items;
} T_DATUM_STRATUM_DUPES;

void datum_stratum_dupes_init(void *vsdata);

#include "datum_stratum.h"

bool datum_stratum_check_for_dupe(T_DATUM_STRATUM_THREADPOOL_DATA *t, const uint8_t *share_hash, uint64_t job_tsms);
void datum_stratum_dupes_cleanup(T_DATUM_STRATUM_DUPES *dupes, bool full_wipe);

#endif
